package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/ux"
	"github.com/spf13/cobra"
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
	rootCmd := app.newRootCommand(ctx)
	rootCmd.SetArgs(args)
	rootCmd.SetOut(app.stdout)
	rootCmd.SetErr(app.stderr)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		var cmdErr *commandError
		if errors.As(err, &cmdErr) {
			cmdErr.write(app.stderr)
			return cmdErr.code
		}

		fmt.Fprintf(app.stderr, "%v\n\n", err)
		app.printRootHelp(app.stderr)
		return int(model.ExitCodeUsageError)
	}

	return 0
}

func (app App) printRootHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.RootHelp()))
	fmt.Fprintln(writer)
}

func (app App) printVersion(writer io.Writer) {
	fmt.Fprintf(writer, "larainspect %s\n", Version)
}

func (app App) newRootCommand(ctx context.Context) *cobra.Command {
	var versionRequested bool

	rootCmd := &cobra.Command{
		Use:           "larainspect",
		Short:         "Read-only Laravel VPS auditor for operators under pressure.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if versionRequested {
				app.printVersion(cmd.OutOrStdout())
				return nil
			}

			app.printRootHelp(cmd.OutOrStdout())
			return nil
		},
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolVar(&versionRequested, "version", false, "print version")
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		app.printRootHelp(cmd.OutOrStdout())
	})
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, app.printRootHelp)
	})

	rootCmd.AddCommand(app.newAuditCommand(ctx))
	rootCmd.AddCommand(app.newControlsCommand())
	rootCmd.AddCommand(app.newVersionCommand())

	return rootCmd
}

func (app App) newVersionCommand() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:           "version",
		Short:         "Print the development version",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			app.printVersion(cmd.OutOrStdout())
		},
	}

	versionCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		app.printVersion(cmd.OutOrStdout())
	})

	return versionCmd
}

type commandError struct {
	code  int
	err   error
	usage func(io.Writer)
}

func (err *commandError) Error() string {
	if err == nil || err.err == nil {
		return ""
	}

	return err.err.Error()
}

func (err *commandError) Unwrap() error {
	if err == nil {
		return nil
	}

	return err.err
}

func (err *commandError) write(writer io.Writer) {
	if err == nil {
		return
	}

	if err.err != nil {
		fmt.Fprintln(writer, err.err)
		if err.usage != nil {
			fmt.Fprintln(writer)
		}
	}

	if err.usage != nil {
		err.usage(writer)
	}
}

func newUsageError(err error, usage func(io.Writer)) *commandError {
	return &commandError{
		code:  int(model.ExitCodeUsageError),
		err:   err,
		usage: usage,
	}
}
