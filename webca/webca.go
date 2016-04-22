package webca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"net"
	"net/http"
	"time"
)

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
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	t := webca.Ca.GetCertificateTemplate(hostNames[0], time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	publickey := &privatekey.PublicKey

	x, err := webca.Ca.CreateCertificate(t, publickey)
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
