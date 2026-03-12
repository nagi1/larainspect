package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

type Specification struct {
	Name            string
	AllowedFlags    map[string]struct{}
	AllowedPrefixes []string
	AllowPaths      bool
	AllowValues     bool
	MaxArgs         int
}

func (specification Specification) Validate(args []string) error {
	if specification.MaxArgs > 0 && len(args) > specification.MaxArgs {
		return fmt.Errorf("command %q received %d args; max is %d", specification.Name, len(args), specification.MaxArgs)
	}

	for _, arg := range args {
		if specification.allowsArgument(arg) {
			continue
		}

		return fmt.Errorf("command %q argument %q is not allowlisted", specification.Name, arg)
	}

	return nil
}

func (specification Specification) allowsArgument(arg string) bool {
	if _, ok := specification.AllowedFlags[arg]; ok {
		return true
	}

	if specification.hasAllowedPrefix(arg) {
		return true
	}

	if specification.AllowPaths && isPathArgument(arg) {
		return true
	}

	return specification.AllowValues && !strings.HasPrefix(arg, "-")
}

func (specification Specification) hasAllowedPrefix(arg string) bool {
	for _, prefix := range specification.AllowedPrefixes {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}

	return false
}

type Allowlist struct {
	mu    sync.RWMutex
	specs map[string]Specification
}

func NewAllowlist(specifications []Specification) *Allowlist {
	specs := make(map[string]Specification, len(specifications))
	for _, specification := range specifications {
		specs[specification.Name] = specification
	}

	return &Allowlist{specs: specs}
}

func DefaultAllowlist() *Allowlist {
	return NewAllowlist([]Specification{
		{Name: "pwd", MaxArgs: 0},
		{Name: "hostname", AllowedFlags: map[string]struct{}{"-f": {}}, MaxArgs: 1},
		{Name: "whoami", MaxArgs: 0},
		{Name: "uname", AllowedFlags: map[string]struct{}{"-a": {}, "-s": {}, "-m": {}, "-r": {}}, MaxArgs: 1},
		{Name: "cat", AllowPaths: true},
		{Name: "readlink", AllowedFlags: map[string]struct{}{"-f": {}, "-n": {}}, AllowPaths: true},
		{Name: "ls", AllowedFlags: map[string]struct{}{"-1": {}, "-A": {}, "-a": {}, "-al": {}, "-d": {}, "-l": {}, "-la": {}, "-n": {}}, AllowPaths: true},
		{Name: "stat", AllowedFlags: map[string]struct{}{"-L": {}, "-c": {}, "-f": {}}, AllowPaths: true, AllowValues: true},
		{Name: "find", AllowedFlags: map[string]struct{}{"-group": {}, "-maxdepth": {}, "-mindepth": {}, "-mmin": {}, "-mtime": {}, "-name": {}, "-path": {}, "-perm": {}, "-print": {}, "-printf": {}, "-type": {}, "-user": {}}, AllowPaths: true, AllowValues: true},
	})
}

func (allowlist *Allowlist) Validate(request model.CommandRequest) error {
	allowlist.mu.RLock()
	specification, ok := allowlist.specs[request.Name]
	allowlist.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrCommandRejected, request.Name)
	}

	if err := specification.Validate(request.Args); err != nil {
		return fmt.Errorf("%w: %v", ErrCommandRejected, err)
	}

	return nil
}

type CommandRunner struct {
	timeout        time.Duration
	maxOutputBytes int
	allowlist      *Allowlist
}

func NewCommandRunner(timeout time.Duration, maxOutputBytes int, allowlist *Allowlist) *CommandRunner {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = 64 * 1024
	}
	if allowlist == nil {
		allowlist = DefaultAllowlist()
	}

	return &CommandRunner{
		timeout:        timeout,
		maxOutputBytes: maxOutputBytes,
		allowlist:      allowlist,
	}
}

var (
	ErrCommandRejected = errors.New("command rejected")
	ErrCommandTimedOut = errors.New("command timed out")
)

func (runner *CommandRunner) Run(ctx context.Context, request model.CommandRequest) (model.CommandResult, error) {
	if err := runner.allowlist.Validate(request); err != nil {
		return model.CommandResult{}, err
	}

	commandContext := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		commandContext, cancel = context.WithTimeout(ctx, runner.timeout)
	}
	defer cancel()

	result := model.CommandResult{
		Command:   request,
		StartedAt: time.Now().UTC(),
	}

	command := exec.CommandContext(commandContext, request.Name, request.Args...)
	stdout := newCaptureBuffer(runner.maxOutputBytes)
	stderr := newCaptureBuffer(runner.maxOutputBytes)
	command.Stdout = stdout
	command.Stderr = stderr

	runErr := command.Run()
	result.FinishedAt = time.Now().UTC()
	result.Duration = result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond).String()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Truncated = stdout.Truncated() || stderr.Truncated()

	switch {
	case runErr == nil:
		result.ExitCode = 0
		return result, nil
	case errors.Is(commandContext.Err(), context.DeadlineExceeded):
		result.TimedOut = true
		result.ExitCode = -1
		return result, fmt.Errorf("%w: %s", ErrCommandTimedOut, request.Name)
	default:
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			result.ExitCode = exitCode(exitError)
			return result, nil
		}

		return result, runErr
	}
}

type captureBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCaptureBuffer(limit int) *captureBuffer {
	return &captureBuffer{limit: limit}
}

func (buffer *captureBuffer) Write(data []byte) (int, error) {
	if buffer.limit <= 0 {
		buffer.truncated = true
		return len(data), nil
	}

	if buffer.buf.Len() >= buffer.limit {
		buffer.truncated = true
		return len(data), nil
	}

	remaining := buffer.limit - buffer.buf.Len()
	if len(data) > remaining {
		buffer.truncated = true
		data = data[:remaining]
	}

	_, err := buffer.buf.Write(data)
	return len(data), err
}

func (buffer *captureBuffer) String() string {
	return buffer.buf.String()
}

func (buffer *captureBuffer) Truncated() bool {
	return buffer.truncated
}

func exitCode(exitError *exec.ExitError) int {
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}

	return 1
}

func isPathArgument(arg string) bool {
	return strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../")
}
