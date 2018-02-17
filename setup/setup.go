package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"ezb_pki/models/config"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ShowMax/go-fqdn"

	"github.com/urfave/cli"
)

func Setup(conf config.Configuration, listen string) error {
	hostname := fqdn.Get()
	// json config
	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		if listen != "" {
			conf.Listen = listen
			c, _ := json.Marshal(conf)
			ioutil.WriteFile("config.json", c, 0600)
			log.Println("Configuration file saved.")
		} else {
			return cli.NewExitError(err, -1)
		}
	} else {
		if listen != "" {
			conf.Listen = listen
			c, _ := json.Marshal(conf)
			ioutil.WriteFile("config.json", c, 0600)
			log.Println("Configuration file saved.")
		}
	}

	// cert folder
	if _, err := os.Stat("cert"); os.IsNotExist(err) {
		err = os.MkdirAll("cert", 0600)
		if err != nil {
			return cli.NewExitError(err, -1)
		}
		log.Println("Make cert folder.")
	}

	// private key
	keyfile := "cert/ca.key"
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		keyOut, _ := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		keyOut.Close()
		log.Println("Private key saved at " + keyfile)

		// ca root
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1653),
			Subject: pkix.Name{
				Organization: []string{"ezBastion"},
				CommonName:   hostname,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		pub := &priv.PublicKey
		caB, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
		if err != nil {
			return cli.NewExitError(err, -1)
		}
		// Public key
		rootCAfile := "cert/ca.crt"
		certOut, err := os.Create(rootCAfile)
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})
		certOut.Close()
		log.Println("Root certificat saved at ", rootCAfile)
	}
	return nil
}
