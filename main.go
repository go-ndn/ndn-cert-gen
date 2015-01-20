package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-ndn/ndn"
)

var (
	identity = flag.String("i", "/ndn/guest/alice", "identity")
	file     = flag.String("f", "default", "file name for private key and certificate")
)

func main() {
	flag.Parse()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	name := ndn.NewName(fmt.Sprintf("%s/KEY/ksk-%d/ID-CERT/%%00%%00", *identity, time.Now().UTC().UnixNano()/1000000))
	ndn.SignKey = ndn.Key{
		Name:       name,
		PrivateKey: rsaKey,
	}
	// private key
	f, err := os.Create(*file + ".pri")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = ndn.SignKey.EncodePrivateKey(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	// public key
	f, err = os.Create(*file + ".ndncert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = ndn.SignKey.EncodeCertificate(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(name, "exported")
}
