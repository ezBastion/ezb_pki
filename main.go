//go:generate goversioninfo

// This file is part of ezBastion.

//     ezBastion is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     ezBastion is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.

//     You should have received a copy of the GNU Affero General Public License
//     along with ezBastion.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ezbastion/ezb_pki/setup"

	"github.com/urfave/cli"
	"golang.org/x/sys/windows/svc"
)

func main() {

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
	}
	if !isIntSess {
		conf, err := setup.CheckConfig()
		if err == nil {
			runService(conf.ServiceName, false)
		}
		return
	}
	app := cli.NewApp()
	app.Name = "ezb_pki"
	app.Version = "0.1.2"
	app.Usage = "Manage PKI for ezBastion nodes."
	app.Commands = []cli.Command{
		{
			Name:  "init",
			Usage: "Genarate config file and root CA certificat.",
			Action: func(c *cli.Context) error {
				err := setup.Setup()
				return err
			},
		}, {
			Name:  "debug",
			Usage: "Start pki deamon .",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig()
				runService(conf.ServiceName, true)
				return nil
			},
		}, {
			Name:  "install",
			Usage: "Add pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig()
				err = installService(conf.ServiceName, conf.ServiceFullName)
				if err != nil {
					log.Fatalf("Install ezb_pki service: %v", err)
				}
				return err
			},
		}, {
			Name:  "remove",
			Usage: "Remove pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig()
				err = removeService(conf.ServiceName)
				if err != nil {
					log.Fatalf("Remove ezb_pki service: %v", err)
				}
				return err
			},
		}, {
			Name:  "start",
			Usage: "Start pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig()
				err = startService(conf.ServiceName)
				if err != nil {
					log.Fatalf("start ezb_pki service: %v", err)
				}
				return err
			},
		}, {
			Name:  "stop",
			Usage: "Stop pki deamon windows service.",
			Action: func(c *cli.Context) error {
				conf, _ := setup.CheckConfig()
				err = controlService(conf.ServiceName, svc.Stop, svc.Stopped)
				if err != nil {
					log.Fatalf("stop ezb_pki service: %v", err)
				}
				return err
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
		https://www.ezbastion.com
		support@ezbastion.com
		`, cli.AppHelpTemplate)

	app.Run(os.Args)
}
