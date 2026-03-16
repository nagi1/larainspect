package views

import (
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestCopyTextToClipboardRunsSelectedCommand(t *testing.T) {
	t.Parallel()

	originalRunClipboardCommand := runClipboardCommand
	originalResolveClipboardBackends := resolveClipboardBackends
	runClipboardCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cat")
	}
	resolveClipboardBackends = func() ([]clipboardBackend, error) {
		return []clipboardBackend{commandClipboardBackend("cat", nil)}, nil
	}
	t.Cleanup(func() {
		runClipboardCommand = originalRunClipboardCommand
		resolveClipboardBackends = originalResolveClipboardBackends
	})

	if err := copyTextToClipboard("hello"); err != nil {
		t.Fatalf("copyTextToClipboard() error = %v", err)
	}
}

func TestCopyTextToClipboardFallsBackWhenFirstBackendFails(t *testing.T) {
	t.Parallel()

	originalResolveClipboardBackends := resolveClipboardBackends
	resolveClipboardBackends = func() ([]clipboardBackend, error) {
		return []clipboardBackend{
			{name: "xclip", copy: func(string) error { return errors.New("exit status 1") }},
			{name: "osc52", copy: func(string) error { return nil }},
		}, nil
	}
	t.Cleanup(func() {
		resolveClipboardBackends = originalResolveClipboardBackends
	})

	if err := copyTextToClipboard("hello"); err != nil {
		t.Fatalf("copyTextToClipboard() error = %v", err)
	}
}

func TestClipboardBackendsForLinuxWaylandPrefersWLClipboard(t *testing.T) {
	t.Parallel()

	backends, err := clipboardBackendsFor("linux", envLookup(map[string]string{
		"WAYLAND_DISPLAY": "wayland-0",
	}), lookPathAvailable("wl-copy"), noOSC52Writer)
	if err != nil {
		t.Fatalf("clipboardBackendsFor() error = %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends) = %d, want 1", len(backends))
	}
	if backends[0].name != "wl-copy" {
		t.Fatalf("backend = %q, want wl-copy", backends[0].name)
	}
}

func TestClipboardBackendsForLinuxX11PrefersXClip(t *testing.T) {
	t.Parallel()

	backends, err := clipboardBackendsFor("linux", envLookup(map[string]string{
		"DISPLAY": ":0",
	}), lookPathAvailable("xclip"), noOSC52Writer)
	if err != nil {
		t.Fatalf("clipboardBackendsFor() error = %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends) = %d, want 1", len(backends))
	}
	if backends[0].name != "xclip" {
		t.Fatalf("backend = %q, want xclip", backends[0].name)
	}

	originalRunClipboardCommand := runClipboardCommand
	var gotArgs []string
	runClipboardCommand = func(name string, args ...string) *exec.Cmd {
		gotArgs = append([]string(nil), args...)
		return exec.Command("cat")
	}
	t.Cleanup(func() {
		runClipboardCommand = originalRunClipboardCommand
	})

	if err := backends[0].copy("hello"); err != nil {
		t.Fatalf("backend.copy() error = %v", err)
	}

	wantArgs := []string{"-selection", "clipboard"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestClipboardBackendsForLinuxFallsBackAcrossDisplayServers(t *testing.T) {
	t.Parallel()

	backends, err := clipboardBackendsFor("linux", envLookup(map[string]string{
		"DISPLAY": ":0",
	}), lookPathAvailable("wl-copy"), noOSC52Writer)
	if err != nil {
		t.Fatalf("clipboardBackendsFor() error = %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends) = %d, want 1", len(backends))
	}
	if backends[0].name != "wl-copy" {
		t.Fatalf("backend = %q, want wl-copy fallback", backends[0].name)
	}
}

func TestClipboardBackendsForLinuxHeadlessPrefersOSC52(t *testing.T) {
	t.Parallel()

	backends, err := clipboardBackendsFor("linux", envLookup(map[string]string{
		"SSH_CONNECTION": "1 2 3 4",
	}), lookPathAvailable("xclip"), stubOSC52Writer)
	if err != nil {
		t.Fatalf("clipboardBackendsFor() error = %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends) = %d, want 1", len(backends))
	}
	if backends[0].name != "osc52" {
		t.Fatalf("backend = %q, want osc52", backends[0].name)
	}
}

func TestClipboardBackendsForLinuxReportsHelpfulError(t *testing.T) {
	t.Parallel()

	_, err := clipboardBackendsFor("linux", envLookup(nil), func(string) (string, error) {
		return "", errors.New("missing")
	}, noOSC52Writer)
	if err == nil {
		t.Fatal("expected error when no Linux clipboard command is available")
	}
	if err.Error() != "no supported Linux clipboard backend found; install wl-copy, xclip, or xsel, or use a terminal with OSC52 clipboard support" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClipboardBackendsForDarwinUsesPBCopy(t *testing.T) {
	t.Parallel()

	backends, err := clipboardBackendsFor("darwin", envLookup(nil), func(string) (string, error) {
		return "", nil
	}, noOSC52Writer)
	if err != nil {
		t.Fatalf("clipboardBackendsFor() error = %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("len(backends) = %d, want 1", len(backends))
	}
	if backends[0].name != "pbcopy" {
		t.Fatalf("backend = %q, want pbcopy", backends[0].name)
	}
}

func TestClipboardBackendsForUnknownOSReturnsError(t *testing.T) {
	t.Parallel()

	_, err := clipboardBackendsFor("plan9", envLookup(nil), func(string) (string, error) {
		return "", nil
	}, noOSC52Writer)
	if err == nil {
		t.Fatal("expected error for unsupported operating system")
	}
}

func TestOSC52ClipboardBackendWrapsTmuxSessions(t *testing.T) {
	t.Parallel()

	var written strings.Builder
	backend := osc52ClipboardBackend(envLookup(map[string]string{
		"TMUX": "/tmp/tmux-1000/default,1234,0",
	}), func() (io.Writer, bool) {
		return &written, true
	})

	if err := backend.copy("hello"); err != nil {
		t.Fatalf("backend.copy() error = %v", err)
	}
	if !strings.Contains(written.String(), "tmux;") {
		t.Fatalf("expected tmux-wrapped OSC52 sequence, got %q", written.String())
	}
	if !strings.Contains(written.String(), "aGVsbG8=") {
		t.Fatalf("expected base64 clipboard payload, got %q", written.String())
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

func noOSC52Writer() (io.Writer, bool) {
	return nil, false
}

func stubOSC52Writer() (io.Writer, bool) {
	return io.Discard, true
}
