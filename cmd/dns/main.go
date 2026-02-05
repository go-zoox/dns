package main

import (
	"github.com/go-zoox/cli"
	"github.com/go-zoox/dns/cmd/dns/commands"
)

func main() {
	app := cli.NewMultipleProgram(&cli.MultipleProgramConfig{
		Name:    "dns",
		Usage:   "A simple and powerful DNS client and server",
		Version: "1.0.0",
	})

	app.Register("client", commands.NewClientCommand())
	app.Register("server", commands.NewServerCommand())

	app.Run()
}
