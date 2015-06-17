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

	"github.com/go-ndn/ndn"
)

var (
	identity   = flag.String("identity", "/ndn/guest/alice", "identity")
	encryption = flag.String("encryption", "rsa", "rsa or ecdsa")
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
			fmt.Println(err)
			return
		}
		key = &ndn.RSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "ecdsa":
		pri, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			fmt.Println(err)
			return
		}
		key = &ndn.ECDSAKey{
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
		fmt.Println(err)
		return
	}
	defer pem.Close()
	err = ndn.EncodePrivateKey(key, pem)
	if err != nil {
		fmt.Println(err)
		return
	}
	// certificate
	cert, err := os.Create(*file + ".ndncert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cert.Close()
	err = ndn.EncodeCertificate(key, cert)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(name, "exported")
}
