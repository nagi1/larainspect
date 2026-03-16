package views

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var runClipboardCommand = exec.Command
var resolveClipboardCommand = clipboardCommand

func copyTextToClipboard(text string) error {
	command, args, err := resolveClipboardCommand()
	if err != nil {
		return err
	}

	cmd := runClipboardCommand(command, args...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

func clipboardCommand() (string, []string, error) {
	return clipboardCommandFor(runtime.GOOS, os.LookupEnv, exec.LookPath)
}

func clipboardCommandFor(goos string, lookupEnv func(string) (string, bool), lookPath func(string) (string, error)) (string, []string, error) {
	switch goos {
	case "darwin":
		return "pbcopy", nil, nil
	case "windows":
		return "clip", nil, nil
	case "linux":
		candidates := linuxClipboardCandidates(lookupEnv)
		for _, candidate := range candidates {
			if _, err := lookPath(candidate.name); err == nil {
				return candidate.name, candidate.args, nil
			}
		}
		return "", nil, fmt.Errorf("no supported Linux clipboard command found; install wl-copy, xclip, or xsel")
	}

	return "", nil, errors.New("no supported clipboard command found for this operating system")
}

type clipboardCandidate struct {
	name string
	args []string
}

func linuxClipboardCandidates(lookupEnv func(string) (string, bool)) []clipboardCandidate {
	wayland := envSet(lookupEnv, "WAYLAND_DISPLAY")
	x11 := envSet(lookupEnv, "DISPLAY")

	waylandCandidates := []clipboardCandidate{
		{name: "wl-copy"},
	}
	x11Candidates := []clipboardCandidate{
		{name: "xclip", args: []string{"-selection", "clipboard"}},
		{name: "xsel", args: []string{"--clipboard", "--input"}},
	}
	portableCandidates := []clipboardCandidate{
		{name: "termux-clipboard-set"},
	}

	var candidates []clipboardCandidate
	switch {
	case wayland:
		candidates = append(candidates, waylandCandidates...)
		candidates = append(candidates, x11Candidates...)
	case x11:
		candidates = append(candidates, x11Candidates...)
		candidates = append(candidates, waylandCandidates...)
	default:
		candidates = append(candidates, waylandCandidates...)
		candidates = append(candidates, x11Candidates...)
	}

	return append(candidates, portableCandidates...)
}

func envSet(lookupEnv func(string) (string, bool), key string) bool {
	value, ok := lookupEnv(key)
	return ok && strings.TrimSpace(value) != ""
}
