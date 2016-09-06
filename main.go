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

func main() {
	var (
		identity string
		keyType  string
		file     string
	)
	flag.StringVar(&identity, "identity", "/ndn/guest/alice", "identity")
	flag.StringVar(&keyType, "type", "rsa", "[ rsa | ecdsa | hmac ]")
	flag.StringVar(&file, "file", "default", "file name for private key and certificate")
	flag.Parse()

	var (
		name = ndn.NewName(fmt.Sprintf("%s/%d/KEY/%%00%%00", identity, time.Now().UnixNano()/1000000))
		key  ndn.Key
	)
	switch keyType {
	case "rsa":
		pri, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Println(err)
			return
		}
		key = &ndn.RSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "ecdsa":
		pri, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			log.Println(err)
			return
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
		log.Println("unsupported key type")
		return
	}
	// private key
	pem, err := os.Create(file + ".pri")
	if err != nil {
		log.Println(err)
		return
	}
	defer pem.Close()
	err = ndn.EncodePrivateKey(key, pem)
	if err != nil {
		log.Println(err)
		return
	}
	// certificate
	cert, err := os.Create(file + ".ndncert")
	if err != nil {
		log.Println(err)
		return
	}
	defer cert.Close()
	err = ndn.EncodeCertificate(key, cert)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(name, "exported")
}
