package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

func NewApp(stdout io.Writer, stderr io.Writer) App {
	return App{stdout: stdout, stderr: stderr}
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
		return runAuditCommand(ctx, app.stdout, app.stderr, args[1:])
	default:
		fmt.Fprintf(app.stderr, "unknown command %q\n\n", args[0])
		app.printRootHelp(app.stderr)
		return 1
	}
}

func (app App) printRootHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(rootHelp))
	fmt.Fprintln(writer)
}

const rootHelp = `
larainspect

Read-only Laravel VPS auditor.

Usage:
  larainspect audit [flags]
  larainspect help
  larainspect version

Examples:
  larainspect audit
  larainspect audit --format json

Commands:
  audit     Run the read-only audit pipeline foundation
  help      Show command help
  version   Print the development version
`

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
