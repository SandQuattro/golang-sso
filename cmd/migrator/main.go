package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log"
	"os"
	"sso/internal/config"
)

// go run ./cmd/migrator -config=conf/application.conf -migrations-path=./migrations
func main() {
	var confFile, migrationsPath, migrationsTable string

	flag.StringVar(&confFile, "config", "application.conf", "-config=<config file name>")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of migrations table")

	flag.Parse()

	config.MustConfig(&confFile)
	conf := config.GetConfig()

	if migrationsPath == "" {
		log.Fatal("migrations path is required")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable", conf.GetString("db.user"), os.Getenv("PGPASS"), conf.GetString("db.host"), conf.GetInt("db.port"), conf.GetString("db.name")),
	)
	if err != nil {
		log.Fatal("error starting migration, ", err.Error())
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("no new migrations to apply")
		}
		log.Fatal(err)
	}

	log.Println("migrations applied successfully")
}
