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
	http.HandleFunc("/certificate", webCa.Handle)
	err = http.ListenAndServe(":"+strconv.Itoa(conf.Web.Port), nil)
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
