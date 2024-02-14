package db

import (
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // added postgres
)

func Connect(config *hocon.Config, dbPass string) *sqlx.DB {
	logger := logdoc.GetLogger()
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.GetString("db.host"),
		config.GetString("db.port"),
		config.GetString("db.user"),
		dbPass,
		config.GetString("db.name"),
		config.GetString("db.ssl"),
	)
	db, err := sqlx.Connect(config.GetString("db.driver"), psqlInfo)
	if err != nil {
		logger.Fatal(fmt.Sprintf("Error connecting database: %s", config.GetString("db.driver")))
	}
	err = db.Ping()
	if err != nil {
		logger.Fatal(fmt.Sprintf("Error pinging database: %s", config.GetString("db.driver")))
	}
	return db
}
