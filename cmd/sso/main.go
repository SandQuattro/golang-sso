package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sso/internal/app/logging"
	"sso/internal/app/utils"
	"sso/internal/config"
	"sso/internal/db"
	"sso/internal/pkg/app"
	"strconv"
	"syscall"

	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/redis/go-redis/v9"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse command line arguments
	confFile := flag.String("config", "conf/application.conf", "Path to the configuration file")
	port := flag.String("port", "9000", "Service port")

	flag.Parse()

	// Load configuration
	config.MustConfig(confFile)
	conf := config.GetConfig()

	// Initialize LogDoc logging subsystem
	conn, err := logging.LDSubsystemInit()
	logger := logdoc.GetLogger()
	if err != nil {
		logger.Error("Error initializing LogDoc subsystem")
	} else {
		logger.Info("LogDoc subsystem initialized successfully")
		if conn != nil {
			defer (*conn).Close()
		}
	}

	// Validate port
	if *port == "" {
		logger.Fatal("Error: port is empty")
	}

	// Create and remove PID file
	pid := utils.CreatePID()
	defer os.Remove("RUNNING_PID_" + strconv.Itoa(pid))

	// Connect to the database
	dbPass := os.Getenv("PGPASS")
	if dbPass == "" {
		logger.Fatal("Database password is empty")
	}

	d := db.Connect(conf, dbPass)
	defer d.Close()

	logger.Info("Database connection successful")

	// Connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", conf.GetString("redis.host"), conf.GetInt("redis.port")),
	})
	defer rdb.Close()

	logger.Info("Attempting to connect to Redis...")
	err = rdb.Ping(ctx).Err()
	if err != nil {
		logger.Error("Failed to ping Redis:", err)
	} else {
		logger.Info("Redis connection successful")
	}

	// Create and run the application
	a, err := app.New(ctx, config.GetConfig, *port, rdb, d)
	if err != nil {
		logger.Fatal("Error creating application:", err)
	}

	go func() {
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		for {
			<-sighup
			logger.Info("Reloading configuration...")
			if err := config.ReloadConfig(confFile); err != nil {
				logger.Error("Error reloading config:", err)
			}
			logger.Info("Configuration reloaded.")
		}
	}()

	go func() {
		logger.Debug("Running server on port:", *port)
		if err := a.Run(); err != nil {
			logger.Fatal("Error running application:", err)
		}
	}()

	// Используем буферизированный канал, как рекомендовано внутри signal.Notify функции
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Блокируемся и ожидаем из канала quit - interrupt signal чтобы сделать gracefully shutdown сервака с таймаутом в 10 сек
	<-quit

	// Получили SIGINT (0x2), выполняем grace shutdown
	logger.Warn("Gracefully shutdown server...")
	if err := a.Echo.Shutdown(ctx); err != nil {
		logger.Error("gracefully shutdown error")
	}
}
