package webca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

var LOGGER = log.New(os.Stdout, "WebCA ", log.Ldate|log.Ltime|log.Lshortfile)

type CertificateResponse struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type WebCa struct {
	Ca   *autoca.AutoCA
	Conf *config.Conf
}

func (webca *WebCa) Handle(rw http.ResponseWriter, req *http.Request) {

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	hostNames, err := net.LookupAddr(host)
	if err != nil || len(hostNames) == 0 {
		LOGGER.Printf("Can't resolve hostnames for %v\n", host)
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	}

	t := webca.Ca.GetHostCertificateTemplate(hostNames, time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		LOGGER.Printf("Can't generate key pair:  %v\n", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	publickey := &privatekey.PublicKey

	x, err := webca.Ca.CreateCertificate(t, publickey)
	if err != nil {
		LOGGER.Printf("Can't create a certificate:  %v\n", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	certOut, keyOut := webca.encodeCertAndKey(x, privatekey)

	cert := CertificateResponse{
		Cert: string(certOut),
		Key:  string(keyOut),
	}

	msg, err := json.Marshal(cert)
	if err != nil {
		LOGGER.Printf("Can't marshal json object %v\n", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Write(msg)
}

func (webca *WebCa) CreateLocalCerts(certFile string, keyFile string) {

	host, err := os.Hostname()
	if err != nil {
		LOGGER.Fatalf("Can't discover local host name %v\n", err)
	}

	hostNames := []string{host}
	if err != nil || len(hostNames) == 0 {
		LOGGER.Fatalf("Can't resolve hostnames for %v\n", host)
	}

	t := webca.Ca.GetHostCertificateTemplate(hostNames, time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		LOGGER.Fatalf("Can't generate key pair:  %v\n", err)
	}

	publickey := &privatekey.PublicKey

	x, err := webca.Ca.CreateCertificate(t, publickey)
	if err != nil {
		LOGGER.Fatalf("Can't create a certificate:  %v\n", err)
	}

	certOut, keyOut := webca.encodeCertAndKey(x, privatekey)
	err = ioutil.WriteFile(certFile, certOut, 0400)
	err = ioutil.WriteFile(keyFile, keyOut, 0400)
}

func (webca *WebCa) encodeCertAndKey(cert []byte, key *rsa.PrivateKey) ([]byte, []byte) {

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certOut, keyOut
}
