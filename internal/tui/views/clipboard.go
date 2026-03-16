package views

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	osc52 "github.com/aymanbagabas/go-osc52/v2"
	"golang.org/x/term"
)

var runClipboardCommand = exec.Command
var resolveClipboardBackends = clipboardBackends

func copyTextToClipboard(text string) error {
	backends, err := resolveClipboardBackends()
	if err != nil {
		return err
	}

	var failures []string
	for _, backend := range backends {
		if err := backend.copy(text); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Sprintf("%s: %v", backend.name, err))
		}
	}

	if len(failures) == 0 {
		return errors.New("no supported clipboard backend available")
	}

	return fmt.Errorf("clipboard copy failed (%s)", strings.Join(failures, "; "))
}

func clipboardBackends() ([]clipboardBackend, error) {
	return clipboardBackendsFor(runtime.GOOS, os.LookupEnv, exec.LookPath, defaultOSC52Writer)
}

func clipboardBackendsFor(goos string, lookupEnv func(string) (string, bool), lookPath func(string) (string, error), osc52Writer func() (io.Writer, bool)) ([]clipboardBackend, error) {
	switch goos {
	case "darwin":
		return []clipboardBackend{commandClipboardBackend("pbcopy", nil)}, nil
	case "windows":
		return []clipboardBackend{commandClipboardBackend("clip", nil)}, nil
	case "linux":
		candidates := linuxClipboardCandidates(lookupEnv)
		backends := make([]clipboardBackend, 0, len(candidates)+1)
		for _, candidate := range candidates {
			if _, err := lookPath(candidate.name); err == nil {
				backends = append(backends, commandClipboardBackend(candidate.name, candidate.args))
			}
		}
		if osc52Supported(lookupEnv, osc52Writer) {
			backends = append(backends, osc52ClipboardBackend(lookupEnv, osc52Writer))
		}
		if len(backends) == 0 {
			return nil, fmt.Errorf("no supported Linux clipboard backend found; install wl-copy, xclip, or xsel, or use a terminal with OSC52 clipboard support")
		}
		return backends, nil
	}

	return nil, errors.New("no supported clipboard command found for this operating system")
}

type clipboardCandidate struct {
	name string
	args []string
}

type clipboardBackend struct {
	name string
	copy func(string) error
}

func commandClipboardBackend(name string, args []string) clipboardBackend {
	return clipboardBackend{
		name: name,
		copy: func(text string) error {
			cmd := runClipboardCommand(name, args...)
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		},
	}
}

func osc52ClipboardBackend(lookupEnv func(string) (string, bool), writer func() (io.Writer, bool)) clipboardBackend {
	return clipboardBackend{
		name: "osc52",
		copy: func(text string) error {
			out, ok := writer()
			if !ok {
				return errors.New("no terminal available for OSC52 clipboard copy")
			}

			sequence := osc52.New(text)
			if envSet(lookupEnv, "TMUX") {
				sequence = sequence.Tmux()
			} else if envSet(lookupEnv, "STY") {
				sequence = sequence.Screen()
			}

			_, err := sequence.WriteTo(out)
			return err
		},
	}
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
		// Linux clipboard binaries require a live display server; without one,
		// rely on portable backends such as OSC52 instead of picking xclip blindly.
	}

	return append(candidates, portableCandidates...)
}

func osc52Supported(lookupEnv func(string) (string, bool), writer func() (io.Writer, bool)) bool {
	if _, ok := writer(); !ok {
		return false
	}

	if termValue, ok := lookupEnv("TERM"); ok && strings.EqualFold(strings.TrimSpace(termValue), "dumb") {
		return false
	}

	knownEnv := []string{
		"SSH_CONNECTION",
		"SSH_TTY",
		"TMUX",
		"STY",
		"TERM_PROGRAM",
		"WT_SESSION",
		"KITTY_WINDOW_ID",
		"KONSOLE_VERSION",
		"VTE_VERSION",
	}
	for _, key := range knownEnv {
		if envSet(lookupEnv, key) {
			return true
		}
	}

	return false
}

func defaultOSC52Writer() (io.Writer, bool) {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		return os.Stderr, true
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		return os.Stdout, true
	}
	return nil, false
}

func envSet(lookupEnv func(string) (string, bool), key string) bool {
	value, ok := lookupEnv(key)
	return ok && strings.TrimSpace(value) != ""
}
