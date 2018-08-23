package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// public key is included in privatekey

	var privatekey *rsa.PrivateKey
	if fileinfo, err := os.Stat("../key/privpem.pem"); err == nil {
		file, err := os.Open("../key/privpem.pem")
		if err != nil {
			log.Fatal("[ERR] can not open private key file")
		}
		defer file.Close()

		readinPrivbytes := make([]byte, fileinfo.Size())
		_, err = file.Read(readinPrivbytes)
		if err != nil {
			log.Fatal("[ERR] can not read in private key")
		}

		block, _ := pem.Decode(readinPrivbytes)
		if block == nil || block.Type != "PRIVATE KEY" {
			fmt.Println("failed to decode PEM block containing private key")
		}

		privatekey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

		fmt.Println("private after readin:", privatekey)

		// read in public ket and convert as string
		pubfileinfo, _ := os.Stat("../key/pubpem.pem")
		pubfile, _ := os.Open("../key/pubpem.pem")
		defer pubfile.Close()

		readinPubbytes := make([]byte, pubfileinfo.Size())
		_, err = pubfile.Read(readinPubbytes)
		if err != nil {
			fmt.Println("can not read in public key")
		}
		s := string(readinPubbytes)
		fmt.Println("try readin byte in string:", s)
		pubsss := strings.Split(s, "\n")[1] + strings.Split(s, "\n")[2]

		pubblock, _ := pem.Decode(readinPubbytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			fmt.Println("failed to decode PEM block containing public key")
		}

		pubs := string(pubblock.Bytes)

		hfunc := sha1.New()
		hfunc.Write([]byte(pubs))
		binary.Write(hfunc, binary.BigEndian, 0)
		id := hfunc.Sum(nil)

	} else {
		// generate private key
		privatekey, _ = rsa.GenerateKey(rand.Reader, 256)
		fmt.Println("generate private:", privatekey)

		// save private key in pem form
		privbytes := x509.MarshalPKCS1PrivateKey(privatekey)
		// ioutil.WriteFile("private.key", privbytes, 0777)
		// fmt.Println("private key saved to private.key")
		privfile, _ := os.Create("../key/privpem.pem")
		var pempriv = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privbytes}
		pem.Encode(privfile, pempriv)
		privfile.Close()

		pubfile, _ := os.Create("../key/pubpem.pem")
		pubbytes, _ := x509.MarshalPKIXPublicKey(privatekey.Public())
		var pempub = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubbytes}
		pem.Encode(pubfile, pempub)
		pubfile.Close()
	}

	// get id
	publickey := privatekey.Public()
	pubbytes, _ := x509.MarshalPKIXPublicKey(publickey)
	fmt.Println("public key in bytes:", pubbytes)

	pubs := string(pubbytes)
	fmt.Println("public key in string:", pubs)

	hfunc := sha1.New()
	hfunc.Write(pubbytes)
	id := hfunc.Sum(nil)
	fmt.Println("hashed id is:", id)

	// testing
	s := "MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALmbYFmvKeysBRb7WtDFMNNntejausHy7DrNM59V2gvFAgMBAAE="
	hfunc2 := sha1.New()
	hfunc2.Write([]byte(s))
	binary.Write(hfunc2, binary.BigEndian, 0)
	id2 := hfunc2.Sum(nil)
	fmt.Println("hashed id with only key in string is:", id2)
}
