package logging

import (
	"fmt"
	"net"
	"path"
	"runtime"
	"sso/internal/config"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/sirupsen/logrus"
)

func LDSubsystemInit() (*net.Conn, error) {
	logger := logdoc.GetLogger()

	conf := config.GetConfig()
	conn, err := logdoc.Init(
		conf.GetString("ld.proto"),
		conf.GetString("ld.host")+":"+conf.GetString("ld.port"),
		conf.GetString("ld.app"),
	)

	if conf.GetBoolean("debug") {
		logger.Formatter = &logrus.TextFormatter{
			ForceColors:     true,
			ForceQuote:      true,
			FullTimestamp:   true,
			TimestampFormat: "02.01.2006 15:04:05.000000",
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := path.Base(f.File)
				return fmt.Sprintf(" %s:%d", filename, f.Line), "" // fmt.Sprintf("%s()", f.Function)
			},
		}
		logger.Warn("!!! Debug mode ON !!!")
	}
	return &conn, err
}
