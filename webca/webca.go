package webca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
)

var LOGGER = log.New(os.Stdout, "WebCA ", log.Ldate|log.Ltime|log.Lshortfile)

type CertificateResponse struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type pkcs8Key struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type WebCa struct {
	Ca   *autoca.AutoCA
	Conf *config.Conf
}

func (webca *WebCa) checkClientIp(req *http.Request) error {

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("Can't parse IP address")
	}

	if !IpMatch(ip, webca.Conf.Web.Hosts) {
		return errors.New(host + " Not Allowed")
	}
	return nil

}

func (webca *WebCa) Handle(rw http.ResponseWriter, req *http.Request) {

	err := webca.checkClientIp(req)
	if err != nil {
		http.Error(rw, "Not authorized: "+err.Error(), http.StatusForbidden)
		return
	}

	switch req.Method {
	case "GET":
		webca.handleGet(rw, req)
	default:
		http.Error(rw, "Unsupported HTTP method: "+req.Method, http.StatusBadRequest)
	}
}

func (webca *WebCa) handleGet(rw http.ResponseWriter, req *http.Request) {

	var t *x509.Certificate

	cn := req.FormValue("cn")
	// id no CN provided use the client's host name
	if len(cn) == 0 {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		hostNames, err := net.LookupAddr(host)
		if err != nil || len(hostNames) == 0 {
			LOGGER.Printf("Can't resolve hostnames for %v\n", host)
			http.Error(rw, err.Error(), http.StatusNotFound)
			return
		}

		t = webca.Ca.GetHostCertificateTemplate(hostNames, time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))

	} else {
		t = webca.Ca.GetUserCertificateTemplate(cn, time.Now(), time.Now().AddDate(0, 0, webca.Conf.Cert.Days))
	}

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

	var certOut, keyOut []byte

	outForm := req.FormValue("out")
	switch outForm {
	case "pkcs8":
		certOut, keyOut = webca.encodePkcs8CertAndKey(x, privatekey)
	case "":
		fallthrough
	case "pkcs1":
		certOut, keyOut = webca.encodePkcs1CertAndKey(x, privatekey)
	default:
		http.Error(rw, "Unsupported out key form: "+outForm, http.StatusBadRequest)
		return
	}

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

	certOut, keyOut := webca.encodePkcs1CertAndKey(x, privatekey)
	err = ioutil.WriteFile(certFile, certOut, 0400)
	if err != nil {
		LOGGER.Fatalf("Failed to write certificate: %v\n", err)
	}
	err = ioutil.WriteFile(keyFile, keyOut, 0400)
	if err != nil {
		LOGGER.Fatalf("Failed to write key: %v\n", err)
	}
}

func rsaToPkcs8(key *rsa.PrivateKey) []byte {

	var pkey pkcs8Key
	pkey.Version = 0
	pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	pkey.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	pkey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	out, _ := asn1.Marshal(pkey)
	return out
}

func (webca *WebCa) encodePkcs1CertAndKey(cert []byte, key *rsa.PrivateKey) ([]byte, []byte) {

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certOut, keyOut
}

func (webca *WebCa) encodePkcs8CertAndKey(cert []byte, key *rsa.PrivateKey) ([]byte, []byte) {

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaToPkcs8(key)})

	return certOut, keyOut
}
