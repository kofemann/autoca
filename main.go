package main

import (
	"flag"
	"github.com/kofemann/autoca/ca"
	"github.com/kofemann/autoca/config"
	"github.com/kofemann/autoca/webca"
	"log"
	"net/http"
	"os"
	"strconv"
)

var configFile = flag.String("c", "config.yml", "path to config file")

func main() {

	flag.Parse()

	conf, err := config.GetConf(*configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v\n", err)
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
