package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func ConnectDB() {
	// dbURL := "postgresql://" + os.Getenv("DATABASE_USERNAME") + ":" + os.Getenv("DATABASE_PASSWORD") + os.Getenv("DATABASE_URL")
	dbURL := os.Getenv("DATABASE_URL")
	log.Println(dbURL)

	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		log.Printf("Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	var greeting string
	err = conn.QueryRow(context.Background(), "select 'Hello, world!'").Scan(&greeting)
	if err != nil {
		log.Printf("QueryRow failed: %v\n", err)
		os.Exit(1)
	}

	log.Println("DB Connected")
}
