package main

import (
	"os"

	"github.com/urfave/cli"

	"yunion.io/x/log"

	"yunion.io/x/yke/cmd"
)

func main() {
	if err := mainErr(); err != nil {
		log.Fatalf("%v", err)
	}
}

func mainErr() error {
	app := cli.NewApp()
	app.Name = "yke"
	app.Version = cmd.Version().String()
	app.Usage = "Yunion Kubernetes Engine, Running kubernetes cluster in the cloud"
	app.Before = func(ctx *cli.Context) error {
		if ctx.GlobalBool("debug") {
			log.SetLogLevelByString(log.Logger(), "debug")
		}
		return nil
	}
	app.Author = "Yunion Technology @ 2018"
	app.Email = ""
	app.Commands = []cli.Command{
		cmd.UpCommand(),
		cmd.RemoveCommand(),
		cmd.VersionCommand(),
		cmd.ConfigCommand(),
		//cmd.EtcdCommand(),
		cmd.CertificateCommand(),
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug,d",
			Usage: "Debug logging",
		},
	}
	return app.Run(os.Args)
}
