package main

import (
	"context"
	"io"
	"os"

	"github.com/nagi/larainspect/internal/cli"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	app := cli.NewAppWithInput(stdin, stdout, stderr)
	return app.Run(ctx, args)
}
