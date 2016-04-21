package autoca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

var LOGGER = log.New(os.Stdout, "AutoCA ", log.Ldate|log.Ltime|log.Lshortfile)

type AutoCA struct {
	cert       *x509.Certificate
	privateKey *rsa.PrivateKey
}

func (ca *AutoCA) Init(certFile string, keyFile string, pass string) error {

	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		LOGGER.Printf("Failed to read certificate file: %v\n", err)
		return err
	}

	c, _ := pem.Decode(data)
	ca.cert, err = x509.ParseCertificate(c.Bytes)
	if err != nil {
		LOGGER.Printf("Failed to decode certificate: %v\n", err)
		return err
	}

	data, err = ioutil.ReadFile(keyFile)
	if err != nil {
		LOGGER.Printf("Failed to read key file: %v\n", err)
		return err
	}

	k, _ := pem.Decode(data)
	key, err := x509.DecryptPEMBlock(k, []byte(pass))
	if err != nil {
		LOGGER.Printf("Failed to decrypt key: %v\n", err)
		return err
	}

	ca.privateKey, err = x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		LOGGER.Printf("Failed to decode key: %v\n", err)
		return err
	}
	return nil
}

func (ca *AutoCA) GetCertificateTemplate(dn string, notBefore time.Time, notAfter time.Time) *x509.Certificate {

	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:            ca.cert.Subject.Country,
			Organization:       ca.cert.Subject.Organization,
			OrganizationalUnit: ca.cert.Subject.OrganizationalUnit,
			Locality:           ca.cert.Subject.Locality,
			Province:           ca.cert.Subject.Province,
			StreetAddress:      ca.cert.Subject.StreetAddress,
			PostalCode:         ca.cert.Subject.PostalCode,
			CommonName:         dn,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	return template
}

func (ca *AutoCA) CreateCertificate(template *x509.Certificate, publicKey *rsa.PublicKey) ([]byte, error) {

	cert, err := x509.CreateCertificate(rand.Reader, template, ca.cert, publicKey, ca.privateKey)
	if err != nil {
		LOGGER.Printf("Failed to create certificate: %v\n", err)
		return nil, err
	}

	return cert, nil

}
