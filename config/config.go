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
		SerialDB string `yaml:"db"`
	}
	Cert struct {
		Days int `yaml:"days"`
	}
	Web struct {
		Port int `yaml:"port"`
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
