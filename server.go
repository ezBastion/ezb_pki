package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"ezb_pki/models/config"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/urfave/cli"
)

func startRootCAServer(serverchan *chan bool) error {
	configuration := config.Configuration{}
	ex, _ := os.Executable()
	exPath := filepath.Dir(ex)
	confFile := path.Join(exPath, "config.json")
	if _, err := os.Stat(confFile); os.IsNotExist(err) {
		log.Println(err)
		return err
	}
	// err := gonfig.GetConf(path.Join(exPath, "config.json"), &configuration)
	// if err != nil {
	// 	panic(err)
	// }
	configFile, err := os.Open(confFile)
	defer configFile.Close()
	if err != nil {
		log.Println(err)
		return err
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&configuration)
	log.Println(confFile, "loaded.")

	caPublicKeyFile, err := ioutil.ReadFile(path.Join(exPath, "cert/"+configuration.ServiceName+"-ca.crt"))
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
	log.Println("Root CA loaded.")
	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile(path.Join(exPath, "cert/"+configuration.ServiceName+"-ca.key"))
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
	log.Println("Private key loaded.")

	listener, err := net.Listen("tcp", configuration.Listen)
	if err != nil {
		cli.NewExitError(err, -1)
	}
	log.Println("Listen at ", configuration.Listen)
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
		// time.Sleep(time.Millisecond * 10)
		go signconn(conn, caCRT, caPrivateKey)
		// select {
		// case _ = <-*serverchan:
		// 	break
		// }
	}

	return nil

	// err = handleCertificateRequest(configuration, caCRT, caPrivateKey)
	// if err != nil {
	// 	return cli.NewExitError(err, -1)
	// }

	// return nil
}

// func handleCertificateRequest(configuration config.Configuration, rootCert *x509.Certificate, privateKey *rsa.PrivateKey) error {

// 	listener, err := net.Listen("tcp", configuration.Listen)
// 	if err != nil {
// 		cli.NewExitError(err, -1)
// 	}
// 	log.Println("Listen at ", configuration.Listen)
// 	defer func() {
// 		listener.Close()
// 		fmt.Println("Listener closed")
// 	}()

// 	for {
// 		// Get net.TCPConn object
// 		_, err := listener.Accept()
// 		// conn, err := listener.Accept()
// 		if err != nil {
// 			cli.NewExitError(err, -1)
// 			break
// 		}

// 		//go signconn(conn, rootCert, privateKey)
// 	}
// 	return nil
// }
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
