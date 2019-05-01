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
	"strconv"
	"sync"
	"time"
)

var LOGGER = log.New(os.Stdout, "AutoCA ", log.Ldate|log.Ltime|log.Lshortfile)

type AutoCA struct {
	cert         *x509.Certificate
	privateKey   *rsa.PrivateKey
	serialDB     string
	serialDBLock sync.Mutex
}

func (ca *AutoCA) Init(certFile string, keyFile string, pass string, db string) error {

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

	var key []byte
	k, _ := pem.Decode(data)
	if pass == "" {
		key = k.Bytes
	} else {
		key, err = x509.DecryptPEMBlock(k, []byte(pass))
		if err != nil {
			LOGGER.Printf("Failed to decrypt key: %v\n", err)
			return err
		}
	}

	ca.privateKey, err = x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		LOGGER.Printf("Failed to decode key: %v\n", err)
		return err
	}
	ca.serialDB = db
	return nil
}

func (ca *AutoCA) GetHostCertificateTemplate(hosts []string, notBefore time.Time, notAfter time.Time) *x509.Certificate {

	dn := sanitizeFQDN(hosts)
	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(ca.nextSerial()),
		Subject: pkix.Name{
			Country:            ca.cert.Subject.Country,
			Organization:       ca.cert.Subject.Organization,
			OrganizationalUnit: ca.cert.Subject.OrganizationalUnit,
			Locality:           ca.cert.Subject.Locality,
			Province:           ca.cert.Subject.Province,
			StreetAddress:      ca.cert.Subject.StreetAddress,
			PostalCode:         ca.cert.Subject.PostalCode,
			CommonName:         dn[0],
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:    dn,
	}

	return template
}

func (ca *AutoCA) GetUserCertificateTemplate(cn string, notBefore time.Time, notAfter time.Time) *x509.Certificate {

	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(ca.nextSerial()),
		Subject: pkix.Name{
			Country:            ca.cert.Subject.Country,
			Organization:       ca.cert.Subject.Organization,
			OrganizationalUnit: ca.cert.Subject.OrganizationalUnit,
			Locality:           ca.cert.Subject.Locality,
			Province:           ca.cert.Subject.Province,
			StreetAddress:      ca.cert.Subject.StreetAddress,
			PostalCode:         ca.cert.Subject.PostalCode,
			CommonName:         cn,
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

func (ca *AutoCA) nextSerial() int64 {

	ca.serialDBLock.Lock()
	var serial int64
	data, err := ioutil.ReadFile(ca.serialDB)
	if err != nil && !os.IsNotExist(err) {
		LOGGER.Printf("Failed to read serial: %v\n", err)
	} else {
		serial, err = strconv.ParseInt(string(data), 10, 64)
	}

	serial++
	err = ioutil.WriteFile(ca.serialDB, []byte(strconv.FormatInt(serial, 10)), 0600)
	if err != nil {
		LOGGER.Printf("Failed to write new serial into %s : %v\n", ca.serialDB, err)
	}
	ca.serialDBLock.Unlock()
	return serial

}

func sanitizeFQDN(hostnames []string) []string {

	sanitized := hostnames[:]
	for i, s := range sanitized {
		if s[len(s)-1] == '.' {
			sanitized[i] = s[:len(s)-1]
		}
	}
	return sanitized
}
