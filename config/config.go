package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
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
		Port         int      `yaml:"port"`
		UseTls       bool     `yaml:"tls"`
		CertFile     string   `yaml:"cert"`
		KeyFile      string   `yaml:"key"`
		Hosts        []string `yaml:"hosts"`
		GenerateCert bool     `yaml:"generate_cert"`
	}
}

func GetConf(file string) (*Conf, error) {

	c := &Conf{}

	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
