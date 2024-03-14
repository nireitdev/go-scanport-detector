package config

import (
	"gopkg.in/yaml.v2"
	"log"
	"os"
)

type Config struct {
	Config struct {
		Device     string `yaml:"device"`
		Ip         string `yaml:"ip"`
		Portrange  string `yaml:"portrange"`
		Portignore string `yaml:"portignore"`
	} `yaml:"config"`

	Redis struct {
		Addr string `yaml:"addr"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
		Db   string `yaml:"db"`
	} `yaml:"redis"`

	Logfile struct {
		Filename  string `yaml:"logfile"`
		Searchreg string `yaml:"searchregex"`
		Filterreg string `yaml:"filterregex"`
	} `yaml:"logparser"`
}

func ReadConfig() *Config {
	cfg := &Config{}
	f, err := os.Open("config.yml")
	if err != nil {
		log.Fatalf("Imposible procesar archivo config: ", err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		log.Fatalf("Imposible procesar archivo config: ", err)
	}

	return cfg
}
