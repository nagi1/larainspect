package views

import (
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestCopyTextToClipboardRunsSelectedCommand(t *testing.T) {
	t.Parallel()

	originalRunClipboardCommand := runClipboardCommand
	runClipboardCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cat")
	}
	t.Cleanup(func() {
		runClipboardCommand = originalRunClipboardCommand
	})

	if err := copyTextToClipboard("hello"); err != nil {
		t.Fatalf("copyTextToClipboard() error = %v", err)
	}
}

func TestClipboardCommandForLinuxWaylandPrefersWLClipboard(t *testing.T) {
	t.Parallel()

	command, args, err := clipboardCommandFor("linux", envLookup(map[string]string{
		"WAYLAND_DISPLAY": "wayland-0",
	}), lookPathAvailable("wl-copy"))
	if err != nil {
		t.Fatalf("clipboardCommandFor() error = %v", err)
	}
	if command != "wl-copy" {
		t.Fatalf("command = %q, want wl-copy", command)
	}
	if len(args) != 0 {
		t.Fatalf("args = %v, want none", args)
	}
}

func TestClipboardCommandForLinuxX11PrefersXClip(t *testing.T) {
	t.Parallel()

	command, args, err := clipboardCommandFor("linux", envLookup(map[string]string{
		"DISPLAY": ":0",
	}), lookPathAvailable("xclip"))
	if err != nil {
		t.Fatalf("clipboardCommandFor() error = %v", err)
	}
	if command != "xclip" {
		t.Fatalf("command = %q, want xclip", command)
	}
	wantArgs := []string{"-selection", "clipboard"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %v, want %v", args, wantArgs)
	}
}

func TestClipboardCommandForLinuxFallsBackAcrossDisplayServers(t *testing.T) {
	t.Parallel()

	command, args, err := clipboardCommandFor("linux", envLookup(map[string]string{
		"DISPLAY": ":0",
	}), lookPathAvailable("wl-copy"))
	if err != nil {
		t.Fatalf("clipboardCommandFor() error = %v", err)
	}
	if command != "wl-copy" {
		t.Fatalf("command = %q, want wl-copy fallback", command)
	}
	if len(args) != 0 {
		t.Fatalf("args = %v, want none", args)
	}
}

func TestClipboardCommandForLinuxReportsHelpfulError(t *testing.T) {
	t.Parallel()

	_, _, err := clipboardCommandFor("linux", envLookup(nil), func(string) (string, error) {
		return "", errors.New("missing")
	})
	if err == nil {
		t.Fatal("expected error when no Linux clipboard command is available")
	}
	if err.Error() != "no supported Linux clipboard command found; install wl-copy, xclip, or xsel" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClipboardCommandForDarwinUsesPBCopy(t *testing.T) {
	t.Parallel()

	command, args, err := clipboardCommandFor("darwin", envLookup(nil), func(string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("clipboardCommandFor() error = %v", err)
	}
	if command != "pbcopy" {
		t.Fatalf("command = %q, want pbcopy", command)
	}
	if len(args) != 0 {
		t.Fatalf("args = %v, want none", args)
	}
}

func TestClipboardCommandForUnknownOSReturnsError(t *testing.T) {
	t.Parallel()

	_, _, err := clipboardCommandFor("plan9", envLookup(nil), func(string) (string, error) {
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error for unsupported operating system")
	}
}

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func lookPathAvailable(names ...string) func(string) (string, error) {
	available := map[string]struct{}{}
	for _, name := range names {
		available[name] = struct{}{}
	}

	return func(name string) (string, error) {
		if _, ok := available[name]; ok {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("missing")
	}
}
