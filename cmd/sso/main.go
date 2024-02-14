package main

import (
	"flag"
	"fmt"
	"github.com/LogDoc-org/logdoc-go-appender/common"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/jmoiron/sqlx"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sso/internal/app/logging"
	"sso/internal/app/utils"
	"sso/internal/app/utils/gs"
	"sso/internal/config"
	"sso/internal/db"
	"sso/internal/pkg/app"
	"strconv"
)

func main() {
	// Первым делом считаем аргументы командной строки
	confFile := flag.String("config", "conf/application.conf", "-config=<config file name>")
	port := flag.String("port", "9000", "-port=<service port>")

	flag.Parse()
	// и подгрузим конфиг
	config.MustConfig(confFile)
	conf := config.GetConfig()

	// Создаем подсистему логгирования LogDoc
	conn, err := logging.LDSubsystemInit()
	logger := logdoc.GetLogger()
	if err == nil {
		logger.Info(fmt.Sprintf(
			"LogDoc subsystem initialized successfully@@source=%s:%d",
			common.GetSourceName(runtime.Caller(0)), // фреймы не скипаем, не exception
			common.GetSourceLineNum(runtime.Caller(0)),
		))
	}

	c := *conn
	if c != nil {
		defer c.Close()
	} else {
		logger.Error("Error LogDoc subsystem initialization")
	}

	if port == nil || *port == "" {
		logger.Fatal(">> Error, port is empty")
	}

	if conf.GetBoolean("debug") {
		logger.Warn("!!! Debug mode ON !!!")
	}

	pid := utils.CreatePID()
	defer func() {
		err := os.Remove("RUNNING_PID_" + strconv.Itoa(pid))
		if err != nil {
			logger.Fatal("Error removing PID file. Exiting...")
		}
	}()

	// Коннектимся к базе
	dbPass := os.Getenv("PGPASS")
	if dbPass == "" {
		logger.Fatal("db password is empty")
	}

	d := db.Connect(conf, dbPass)
	defer func(d *sqlx.DB) {
		err := d.Close()
		if err != nil {
			logger.Fatal(err)
		}
	}(d)
	logger.Info(">> DATABASE CONNECTION SUCCESSFUL")

	// Создадим приложение
	a, err := app.New(conf, *port, d)
	if err != nil {
		logger.Fatal(err)
	}

	go func() {
		// и запустим приложение (веб сервер)
		logger.Debug(fmt.Sprintf(">> RUNNING SERVER ON PORT: %s", *port))
		err = a.Run()
		if err != nil {
			logger.Fatal(err)
		}
	}()
	gs.GraceShutdown(a)
}
