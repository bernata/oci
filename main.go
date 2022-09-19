package main

import (
	"github.com/alecthomas/kong"
)

type CommandLine struct {
	Repository Repository `cmd:"" help:"Repository commands"`
	Manifest   Manifest   `cmd:"" help:"Manifest commands"`
	Sign       Sign       `cmd:"" help:"Sign"`
}

func main() {
	var commandLine CommandLine
	cmdContext := kong.Parse(&commandLine)

	err := cmdContext.Run()

	cmdContext.FatalIfErrorf(err)
}
