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
	"github.com/sirupsen/logrus"
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
	log := logrus.WithFields(logrus.Fields{
		"name":     name,
		"identity": identity,
		"type":     keyType,
		"file":     file,
	})
	switch keyType {
	case "rsa":
		pri, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Error(err)
			return
		}
		key = &ndn.RSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "ecdsa":
		pri, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			log.Error(err)
			return
		}
		key = &ndn.ECDSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case "hmac":
		// 256 / 8 = 32
		pri := make([]byte, 32)
		_, err := rand.Read(pri)
		if err != nil {
			log.Error(err)
			return
		}
		key = &ndn.HMACKey{
			Name:       name,
			PrivateKey: pri,
		}
	default:
		log.Error("unsupported key type")
		return
	}
	// private key
	pem, err := os.Create(file + ".pri")
	if err != nil {
		log.Error(err)
		return
	}
	defer pem.Close()
	err = ndn.EncodePrivateKey(key, pem)
	if err != nil {
		log.Error(err)
		return
	}
	// certificate
	cert, err := os.Create(file + ".ndncert")
	if err != nil {
		log.Error(err)
		return
	}
	defer cert.Close()
	err = ndn.EncodeCertificate(key, cert)
	if err != nil {
		log.Error(err)
		return
	}
	log.Info("key exported")
}
