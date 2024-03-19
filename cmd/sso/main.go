package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/LogDoc-org/logdoc-go-appender/common"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	// Trying to connect to redis
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", conf.GetString("redis.host"), conf.GetInt("redis.port")),
	})
	defer rdb.Close()

	logger.Info("Trying to connect to redis...")
	err = rdb.Ping(context.Background()).Err()
	if err != nil {
		logrus.Error(fmt.Errorf("failed to ping redis: %w", err))
		rdb.Close()
		rdb = nil
	}
	logger.Info(">> REDIS CONNECTION SUCCESSFUL")

	// Создадим приложение
	a, err := app.New(ctx, conf, *port, rdb, d)
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
	gs.GraceShutdown(ctx, a)
}
