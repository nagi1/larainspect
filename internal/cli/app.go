package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nagi/larainspect/internal/model"
	"github.com/nagi/larainspect/internal/ux"
)

type App struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func NewApp(stdout io.Writer, stderr io.Writer) App {
	return NewAppWithInput(os.Stdin, stdout, stderr)
}

func NewAppWithInput(stdin io.Reader, stdout io.Writer, stderr io.Writer) App {
	return App{stdin: stdin, stdout: stdout, stderr: stderr}
}

func (app App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		app.printRootHelp(app.stdout)
		return 0
	}

	switch args[0] {
	case "help", "--help", "-h":
		app.printRootHelp(app.stdout)
		return 0
	case "version", "--version":
		fmt.Fprintln(app.stdout, "larainspect dev")
		return 0
	case "audit":
		return runAuditCommandWithInput(ctx, app.stdin, app.stdout, app.stderr, args[1:])
	default:
		fmt.Fprintf(app.stderr, "unknown command %q\n\n", args[0])
		app.printRootHelp(app.stderr)
		return int(model.ExitCodeUsageError)
	}
}

func (app App) printRootHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.RootHelp()))
	fmt.Fprintln(writer)
}

func newFlagSet(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	return flagSet
}

func writeFlagError(writer io.Writer, err error, usage func(io.Writer)) {
	if err == nil {
		return
	}

	if !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(writer, err)
		fmt.Fprintln(writer)
	}
	usage(writer)
}
