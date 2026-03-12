package main

import (
	"context"
	"os"

	"github.com/nagi/larainspect/internal/cli"
)

func main() {
	app := cli.NewApp(os.Stdout, os.Stderr)
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
