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

package setup

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ezbastion/ezb_pki/models/config"

	"github.com/ShowMax/go-fqdn"

	"github.com/urfave/cli"
)

func CheckConfig(isIntSess bool) (*config.Configuration, error) {
	conf := config.Configuration{}
	ex, _ := os.Executable()
	exPath := filepath.Dir(ex)
	confFile := path.Join(exPath, "config.json")
	if _, err := os.Stat(confFile); os.IsNotExist(err) {
		if isIntSess {
			return Setup("", "", "")
		}
		return nil, err
	}
	configFile, err := os.Open(confFile)
	defer configFile.Close()
	if err != nil {
		if isIntSess {
			return Setup("", "", "")
		}
		return nil, err
	}
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&conf)
	if err != nil {
		if isIntSess {
			return Setup("", "", "")
		}
		return nil, err
	}
	return &conf, nil
}

func Setup(listen string, name string, fullname string) (*config.Configuration, error) {
	conf := config.Configuration{}
	fqdn := fqdn.Get()
	hostname, _ := os.Hostname()
	ex, _ := os.Executable()
	exPath := filepath.Dir(ex)
	confFile := path.Join(exPath, "config.json")
	if _, err := os.Stat(confFile); os.IsNotExist(err) {
		rxListen := regexp.MustCompile("^[\\.0-9|\\w]*:[0-9]{1,5}$")
		if rxListen.MatchString(listen) {
			conf.Listen = listen
		} else {
			fmt.Println("\nWhich port do you want to listen to?")
			fmt.Println("ex: :5010, 0.0.0.0:5100, localhost:7800, name.domain:2000 ...")
			for {
				listen = askForValue("listen", "^[\\.0-9|\\w]*:[0-9]{1,5}$")
				c := askForConfirmation(fmt.Sprintf("Listen on (%s) ok?", listen))
				if c {
					conf.Listen = listen
					break
				}
			}
		}
		rxName := regexp.MustCompile("^[\\w-]+$")
		if rxName.MatchString(name) {
			conf.ServiceName = name
		} else {
			fmt.Println("\nWhat is service name?")
			fmt.Println("ex: ezb_pki, myPKI-p5010, api-pki-uat ...")
			for {
				name = askForValue("name", "^[\\w-]+$")
				c := askForConfirmation(fmt.Sprintf("Service name (%s) ok?", name))
				if c {
					conf.ServiceName = name
					break
				}
			}
		}
		rxFull := regexp.MustCompile("^[\\w -]+$")
		if rxFull.MatchString(fullname) {
			conf.ServiceFullName = fullname
		} else {
			fmt.Println("\nWhat is service full name?")
			fmt.Println("ex: my pki service, Api PKI for UAT ...")
			for {
				fullname = askForValue("full name", "^[\\w -]+$")
				c := askForConfirmation(fmt.Sprintf("Service full name (%s) ok?", fullname))
				if c {
					conf.ServiceFullName = fullname
					break
				}
			}
		}
		c, _ := json.Marshal(conf)
		ioutil.WriteFile(path.Join(exPath, "config.json"), c, 0600)
		log.Println("config.json saved.")
	} else {
		configFile, err := os.Open(confFile)
		defer configFile.Close()
		if err != nil {
			return nil, err
		}
		jsonParser := json.NewDecoder(configFile)
		err = jsonParser.Decode(&conf)
		if err != nil {
			log.Println(err)
			if listen != "" {
				conf.Listen = listen
			} else {
				fmt.Println("Which port do you want to listen to?")
				fmt.Println("ex: :5010, 0.0.0.:5100, localhost:7800, name.domain:2000 ...")
				for {
					listen = askForValue("listen", "^[\\.0-9|\\w]*:[0-9]{1,5}$")
					c := askForConfirmation(fmt.Sprintf("Listen on (%s) ok?", listen))
					if c {
						conf.Listen = listen
						break
					}
				}
			}
			if name != "" {
				conf.ServiceName = name
			} else {
				fmt.Println("What is service name?")
				fmt.Println("ex: ezb_pki, myPKI-p5010, api-pki-uat ...")
				for {
					name = askForValue("name", "^[\\w-]*$")
					c := askForConfirmation(fmt.Sprintf("Service name (%s) ok?", name))
					if c {
						conf.ServiceName = name
						break
					}
				}
			}
			if fullname != "" {
				conf.ServiceFullName = fullname
			} else {
				fmt.Println("What is service full name?")
				fmt.Println("ex: my pki service, Api PKI for UAT ...")
				for {
					fullname = askForValue("full name", "^[\\w -]*$")
					c := askForConfirmation(fmt.Sprintf("Service full name (%s) ok?", fullname))
					if c {
						conf.ServiceFullName = fullname
						break
					}
				}
			}
			c, _ := json.Marshal(conf)
			ioutil.WriteFile(confFile, c, 0600)
			log.Println("config.json saved.")
		} else {
			needSave := false
			rxListen := regexp.MustCompile("^[\\.0-9|\\w]*:[0-9]{1,5}$")
			if rxListen.MatchString(listen) && listen != conf.Listen {
				conf.Listen = listen
				needSave = true
			} else if conf.Listen == "" {
				fmt.Println("\nWhich port do you want to listen to?")
				fmt.Println("ex: :5010, 0.0.0.0:5100, localhost:7800, name.domain:2000 ...")
				for {
					listen = askForValue("listen", "^[\\.0-9|\\w]*:[0-9]{1,5}$")
					c := askForConfirmation(fmt.Sprintf("Listen on (%s) ok?", listen))
					if c {
						conf.Listen = listen
						needSave = true
						break
					}
				}
			} else if !rxListen.MatchString(listen) && listen != "" {
				log.Println("Bad listen format. Exit")
				return nil, errors.New("bad listen format")
			}
			rxName := regexp.MustCompile("^[\\w-]+$")
			if rxName.MatchString(name) && name != conf.ServiceName {
				conf.ServiceName = name
				needSave = true
			} else if conf.ServiceName == "" {
				fmt.Println("\nWhat is service name?")
				fmt.Println("ex: ezb_pki, myPKI-p5010, api-pki-uat ...")
				for {
					name = askForValue("name", "^[\\w-]+$")
					c := askForConfirmation(fmt.Sprintf("Service name (%s) ok?", name))
					if c {
						conf.ServiceName = name
						needSave = true
						break
					}
				}
			} else if !rxName.MatchString(name) && name != "" {
				log.Println("Bad service name format. Exit")
				return nil, errors.New("bad service name format")
			}
			rxFull := regexp.MustCompile("^[\\w -]+$")
			if rxFull.MatchString(fullname) && fullname != conf.ServiceFullName {
				conf.ServiceFullName = fullname
				needSave = true
			} else if conf.ServiceFullName == "" {
				fmt.Println("\nWhat is service full name?")
				fmt.Println("ex: my pki service, Api PKI for UAT ...")
				for {
					fullname = askForValue("full name", "^[\\w -]+$")
					c := askForConfirmation(fmt.Sprintf("Service full name (%s) ok?", fullname))
					if c {
						conf.ServiceFullName = fullname
						needSave = true
						break
					}
				}
			} else if !rxFull.MatchString(fullname) && fullname != "" {
				log.Println("Bad service full name format. Exit")
				return nil, errors.New("bad service full name format")
			}
			if needSave {
				c, _ := json.Marshal(conf)
				ioutil.WriteFile(path.Join(exPath, "config.json"), c, 0600)
				log.Println("config.json updated.")
			}
		}
	}

	if _, err := os.Stat(path.Join(exPath, "cert")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(exPath, "cert"), 0600)
		if err != nil {
			return nil, cli.NewExitError(err, -1)
		}
		log.Println("Make cert folder.")
	}

	keyfile := path.Join(exPath, "cert/"+conf.ServiceName+"-ca.key")
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		keyOut, _ := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		b, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			panic(err)
		}
		pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		keyOut.Close()
		log.Println("Private key saved at " + keyfile)

		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1653),
			Subject: pkix.Name{
				Organization: []string{"ezBastion"},
				CommonName:   conf.ServiceName,
			},
			DNSNames:              []string{hostname, fqdn},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		}
		pub := &priv.PublicKey
		caB, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
		if err != nil {
			return nil, cli.NewExitError(err, -1)
		}

		rootCAfile := path.Join(exPath, "cert/"+conf.ServiceName+"-ca.crt")
		certOut, err := os.Create(rootCAfile)
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})
		certOut.Close()
		log.Println("Root certificat saved at ", rootCAfile)
	}
	return nil, nil
}

func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}
func askForValue(s string, pattern string) string {
	reader := bufio.NewReader(os.Stdin)
	re := regexp.MustCompile(pattern)
	for {
		fmt.Printf("%s: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.TrimSpace(response)

		if re.MatchString(response) {
			return response
		}
		fmt.Printf("[%s] wrong format, must match (%s)\n", response, pattern)
	}
}
