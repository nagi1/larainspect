package debuglog

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

// Logger writes developer-oriented audit diagnostics to a single output stream.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a logger that writes to the provided stream.
func New(writer io.Writer) *Logger {
	return &Logger{w: writer}
}

// OpenFile creates a debug logger backed by the given file path.
func OpenFile(path string) (*Logger, io.Closer, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}

	return New(file), file, nil
}

func (logger *Logger) LogProgressEvent(event progress.Event) {
	if logger == nil {
		return
	}

	at := event.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	logger.writeLine(
		at,
		"progress",
		field("type", string(event.Type)),
		field("stage", string(event.Stage)),
		field("component", event.ComponentID),
		field("message", event.Message),
		intField("completed", event.Completed),
		intField("total", event.Total),
		intField("findings", event.Findings),
		intField("unknowns", event.Unknowns),
		field("severity", string(event.Severity)),
		field("title", event.Title),
		errorField("err", event.Err),
	)
}

func (logger *Logger) LogCommand(result model.CommandResult, err error) {
	if logger == nil {
		return
	}

	at := result.FinishedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}

	logger.writeLine(
		at,
		"command",
		field("name", result.Command.Name),
		field("args", strings.Join(result.Command.Args, " ")),
		intField("exit_code", result.ExitCode),
		field("duration", result.Duration),
		boolField("timed_out", result.TimedOut),
		boolField("truncated", result.Truncated),
		intField("stdout_bytes", len(result.Stdout)),
		intField("stderr_bytes", len(result.Stderr)),
		field("stdout", compact(result.Stdout)),
		field("stderr", compact(result.Stderr)),
		errorField("err", err),
	)
}

func (logger *Logger) writeLine(at time.Time, kind string, parts ...string) {
	logger.mu.Lock()
	defer logger.mu.Unlock()

	filtered := make([]string, 0, len(parts)+1)
	filtered = append(filtered, kind)
	for _, part := range parts {
		if part == "" {
			continue
		}
		filtered = append(filtered, part)
	}

	_, _ = fmt.Fprintf(logger.w, "%s %s\n", at.UTC().Format(time.RFC3339Nano), strings.Join(filtered, " "))
}

func field(key string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	return key + "=" + strconv.QuoteToASCII(value)
}

func intField(key string, value int) string {
	return fmt.Sprintf("%s=%d", key, value)
}

func boolField(key string, value bool) string {
	return fmt.Sprintf("%s=%t", key, value)
}

func errorField(key string, err error) string {
	if err == nil {
		return ""
	}

	return field(key, err.Error())
}

func compact(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	return strings.Join(strings.Fields(value), " ")
}
