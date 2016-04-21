package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"os"
	"time"
)

func main() {

	conf, err := config.GetConf()
	if err != nil {
		os.Exit(1)
	}

	ca := &autoca.AutoCA{}
	err = ca.Init(conf.CA.CertFile, conf.CA.KeyFile, conf.CA.KeyPass)
	if err != nil {
		os.Exit(2)
	}

	t := ca.GetCertificateTemplate("localhost", time.Now(), time.Now().AddDate(0, 0, conf.Cert.Days))

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	publickey := &privatekey.PublicKey

	x, err := ca.CreateCertificate(t, publickey)
	if err == nil {
		fmt.Printf("%v\n", x)
	}
}
