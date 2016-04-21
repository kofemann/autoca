package main

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
	"strconv"
	"time"
)

type CertificateResponse struct {
	Cert string `json:"cert"`
	Key  string `json:"Key"`
}

type WebCa struct {
	ca   *autoca.AutoCA
	conf *config.Conf
}

func (webca *WebCa) handle(rw http.ResponseWriter, req *http.Request) {

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	hostNames, err := net.LookupAddr(host)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	t := webca.ca.GetCertificateTemplate(hostNames[0], time.Now(), time.Now().AddDate(0, 0, webca.conf.Cert.Days))

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	publickey := &privatekey.PublicKey

	x, err := webca.ca.CreateCertificate(t, publickey)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})

	cert := CertificateResponse{
		Cert: string(certOut),
		Key:  string(keyOut),
	}

	msg, err := json.Marshal(cert)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
	rw.Write(msg)
}

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

	webca := &WebCa{ca: ca, conf: conf}
	http.HandleFunc("/certificate", webca.handle)
	err = http.ListenAndServe(":"+strconv.Itoa(conf.Web.Port), nil)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
