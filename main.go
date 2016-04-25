package main

import (
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"github.com/kofemann/autoca/webca"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {

	conf, err := config.GetConf()
	if err != nil {
		os.Exit(1)
	}

	ca := &autoca.AutoCA{}
	err = ca.Init(conf.CA.CertFile, conf.CA.KeyFile, conf.CA.KeyPass, conf.CA.SerialDB)
	if err != nil {
		os.Exit(2)
	}

	webCa := &webca.WebCa{Ca: ca, Conf: conf}

	if conf.Web.GenerateCert {
		_, err := os.Stat(conf.Web.CertFile)
		if err != nil && os.IsNotExist(err) {
			webCa.CreateLocalCerts(conf.Web.CertFile, conf.Web.KeyFile)
		}
	}

	http.HandleFunc("/v1/certificate", webCa.Handle)
	err = http.ListenAndServeTLS(":"+strconv.Itoa(conf.Web.Port), conf.Web.CertFile, conf.Web.KeyFile, nil)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
