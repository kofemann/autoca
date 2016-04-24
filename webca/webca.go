package webca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

var LOGGER = log.New(os.Stdout, "WebCA ", log.Ldate|log.Ltime|log.Lshortfile)

type CertificateResponse struct {
	Cert string `json:"cert"`
	Key  string `json:"Key"`
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

	t := webca.Ca.GetCertificateTemplate(hostNames[0], time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))

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

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})

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