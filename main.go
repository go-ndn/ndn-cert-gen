package main

import (
	"crypto"
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
		pri crypto.PrivateKey
		err error
	)
	switch *encryption {
	case "rsa":
		pri, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa":
		pri, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	default:
		flag.PrintDefaults()
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	name := ndn.NewName(fmt.Sprintf("%s/KEY/ksk-%d/ID-CERT/%%00%%00", *identity, time.Now().UTC().UnixNano()/1000000))
	key := ndn.Key{
		Name:       name,
		PrivateKey: pri,
	}
	// private key
	f, err := os.Create(*file + ".pri")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = key.EncodePrivateKey(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	// certificate
	f, err = os.Create(*file + ".ndncert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = key.EncodeCertificate(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(name, "exported")
}
