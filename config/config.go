package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Conf struct {
	CA struct {
		CertFile string `yaml:"cert"`
		KeyFile  string `yaml:"key"`
		KeyPass  string `yaml:"key_pass"`
	}
	Cert struct {
		Days int `yaml:"days"`
	}
}

func GetConf() (*Conf, error) {

	c := &Conf{}

	yamlFile, err := ioutil.ReadFile("config.yml")
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
