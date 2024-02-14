package config

import (
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
)

var config *hocon.Config

func GetConfig() *hocon.Config {
	return config
}

func MustConfig(confFile *string) {
	logger := logdoc.GetLogger()
	c, e := hocon.ParseResource(*confFile)
	if e != nil {
		logger.Fatal("Error reading app configuration file. Exiting...")
	}
	config = c
}
