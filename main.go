package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-ndn/log"
	"github.com/go-ndn/ndn"
)

var (
	identity   = flag.String("identity", "/ndn/guest/alice", "identity")
	encryption = flag.String("encryption", "rsa", "[ rsa | ecdsa | hmac ]")
	file       = flag.String("file", "default", "file name for private key and certificate")
)

func main() {
	flag.Parse()

	var (
		name = ndn.NewName(fmt.Sprintf("%s/%d/KEY/%%00%%00", *identity, time.Now().UTC().UnixNano()/1000000))
		key  ndn.Key
	)
	switch *encryption {
	case "rsa":
		pri, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalln(err)
		}
		key = &ndn.RSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "ecdsa":
		pri, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			log.Fatalln(err)
		}
		key = &ndn.ECDSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "hmac":
		// 256 / 8 = 32
		pri := make([]byte, 32)
		rand.Read(pri)
		key = &ndn.HMACKey{
			Name:       name,
			PrivateKey: pri,
		}
	default:
		flag.PrintDefaults()
		return
	}
	// private key
	pem, err := os.Create(*file + ".pri")
	if err != nil {
		log.Fatalln(err)
	}
	defer pem.Close()
	err = ndn.EncodePrivateKey(key, pem)
	if err != nil {
		log.Fatalln(err)
	}
	// certificate
	cert, err := os.Create(*file + ".ndncert")
	if err != nil {
		log.Fatalln(err)
	}
	defer cert.Close()
	err = ndn.EncodeCertificate(key, cert)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(name, "exported")
}
