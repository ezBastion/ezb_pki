//go:generate goversioninfo -icon=icon.ico
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"ezb_pki/models/config"
	"ezb_pki/setup"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/tkanos/gonfig"
	"github.com/urfave/cli"
)

func main() {
	conf := config.Configuration{}
	app := cli.NewApp()
	app.Name = "ezb_pki"
	app.Version = "0.1.0"
	app.Usage = "Manage PKI for ezBastion nodes."
	app.Commands = []cli.Command{
		{
			Name:      "init",
			ShortName: "i",
			Usage:     "Genarate config file and root CA certificat.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "listen, l",
					Usage: "The TCP address and port to listen to requests on.",
					// Value: "0.0.0.0:5010",
				},
			},
			Action: func(c *cli.Context) error {
				return setup.Setup(conf, c.String("listen"))
			},
		}, {
			Name:      "serve",
			ShortName: "s",
			Usage:     "Start pki deamon.",
			Action: func(c *cli.Context) error {
				ex, _ := os.Executable()
				exPath := filepath.Dir(ex)
				err := gonfig.GetConf(path.Join(exPath, "config.json"), &conf)
				// err := gonfig.GetConf("./config.json", &conf)
				if err != nil {
					panic(err)
				}
				return startRootCAServer(&conf)
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
	fmt.Println(conf.Listen)
	app.Run(os.Args)
}

func startRootCAServer(conf *config.Configuration) error {
	caPublicKeyFile, err := ioutil.ReadFile("cert/ca.crt")
	if err != nil {
		cli.NewExitError(err, -1)
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		cli.NewExitError(err, -1)
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		cli.NewExitError(err, -1)
	}

	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile("cert/ca.key")
	if err != nil {
		cli.NewExitError(err, -1)
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		cli.NewExitError(err, -1)
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		cli.NewExitError(err, -1)
	}
	err = handleCertificateRequest(conf, caCRT, caPrivateKey)
	if err != nil {
		return cli.NewExitError(err, -1)
	}

	return nil
}

func handleCertificateRequest(conf *config.Configuration, rootCert *x509.Certificate, privateKey *rsa.PrivateKey) error {
	listener, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		cli.NewExitError(err, -1)
	}
	log.Println("Listen at ", conf.Listen)
	defer func() {
		listener.Close()
		fmt.Println("Listener closed")
	}()

	for {
		// Get net.TCPConn object
		conn, err := listener.Accept()
		if err != nil {
			cli.NewExitError(err, -1)
			break
		}

		go signconn(conn, rootCert, privateKey)
	}
	return nil
}
func signconn(conn net.Conn, rootCert *x509.Certificate, privateKey *rsa.PrivateKey) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	_, err := reader.Read(header)
	if err != nil {
		log.Println(err)
		return err
	}
	asn1DataSize := binary.LittleEndian.Uint16(header)

	// Now read that number of bytes and parse the certificate request
	asn1Data := make([]byte, asn1DataSize)
	_, err = reader.Read(asn1Data)
	if err != nil {
		log.Println(err)
		return err
	}
	clientCSR, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		log.Println(err)
		return err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		log.Println(err)
		return err
	}
	clientCRTTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,
		PublicKey:          clientCSR.PublicKey,
		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		Issuer:             rootCert.Subject,
		Subject:            clientCSR.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
	certData, err := x509.CreateCertificate(rand.Reader, clientCRTTemplate, rootCert, clientCSR.PublicKey, privateKey)
	if err != nil {
		log.Println(err)
		return err
	}
	writer := bufio.NewWriter(conn)
	// The number of bytes that make up the new certificate go first.
	certHeader := make([]byte, 2)
	binary.LittleEndian.PutUint16(certHeader, uint16(len(certData)))
	_, err = writer.Write(certHeader)
	if err != nil {
		log.Println(err)
		return err
	}
	// Now write the certificate data.
	_, err = writer.Write(certData)
	if err != nil {
		log.Println(err)
		return err
	}
	// Now write the size of the root certificate, which will be needed to validate the new certificate
	rootCertHeader := make([]byte, 2)
	binary.LittleEndian.PutUint16(rootCertHeader, uint16(len(rootCert.Raw)))
	_, err = writer.Write(rootCertHeader)
	if err != nil {
		log.Println(err)
		return err
	}
	// Now write the root certificate data.
	_, err = writer.Write(rootCert.Raw)
	if err != nil {
		log.Println(err)
		return err
	}
	// Flush all the data.
	err = writer.Flush()
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("Transmitted client Certificate to ", clientCSR.Subject.CommonName)

	return nil
}
