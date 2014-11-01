package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/taylorchu/ndn"
	"os"
	"time"
)

var (
	identity = flag.String("i", "/testing/key", "identity")
	file     = flag.String("f", "default", "file name for private key and certificate")
)

func main() {
	flag.Parse()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	name := ndn.NewName(fmt.Sprintf("%s/ksk-%d", *identity, time.Now().UTC().UnixNano()/1000000))
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
	fmt.Println(name.CertificateName(), "exported")
}
