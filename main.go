//go:generate goversioninfo -icon=icon.ico
package main

import (
	"ezb_pki/setup"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
	"golang.org/x/sys/windows/svc"
)

func main() {
	// const svcName = "ezb_pki"
	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
	}
	if !isIntSess {
		conf, err := setup.CheckConfig(false)
		if err == nil {
			runService(conf.ServiceName, false)
		}
		return
	}
	app := cli.NewApp()
	app.Name = "ezb_pki"
	app.Version = "0.1.0"
	app.Usage = "Manage PKI for ezBastion nodes."
	app.Commands = []cli.Command{
		{
			Name:  "init",
			Usage: "Genarate config file and root CA certificat.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name, n",
					Usage: "Windows service name.",
					// Value: "ezb_pki",
				}, cli.StringFlag{
					Name:  "fullname, f",
					Usage: "Windows service full name.",
					// Value: "ezBastion PKI",
				}, cli.StringFlag{
					Name:  "listen, l",
					Usage: "The TCP address and port to listen to requests on.",
					// Value: "0.0.0.0:5010",
				},
			},
			Action: func(c *cli.Context) error {
				_, err := setup.Setup(c.String("listen"), c.String("name"), c.String("fullname"))
				return err
			},
		}, {
			Name:  "debug",
			Usage: "Start pki deamon .",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				runService(conf.ServiceName, true)
				return nil
			},
		}, {
			Name:  "install",
			Usage: "Add pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return installService(conf.ServiceName, conf.ServiceFullName)
			},
		}, {
			Name:  "remove",
			Usage: "Remove pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return removeService(conf.ServiceName)
			},
		}, {
			Name:  "start",
			Usage: "Start pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return startService(conf.ServiceName)
			},
		}, {
			Name:  "stop",
			Usage: "Stop pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig(true)
				return controlService(conf.ServiceName, svc.Stop, svc.Stopped)
			},
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`

		███████╗███████╗██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗
		██╔════╝╚══███╔╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
		█████╗    ███╔╝ ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║
		██╔══╝   ███╔╝  ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║
		███████╗███████╗██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║
		╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
																			   
								██████╗ ██╗  ██╗██╗                            
								██╔══██╗██║ ██╔╝██║                            
								██████╔╝█████╔╝ ██║                            
								██╔═══╝ ██╔═██╗ ██║                            
								██║     ██║  ██╗██║                            
								╚═╝     ╚═╝  ╚═╝╚═╝                            
																			  
%s
INFO:
		http://www.ezbastion.com		
		support@ezbastion.com
		`, cli.AppHelpTemplate)

	app.Run(os.Args)
}
