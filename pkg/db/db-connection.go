package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

var Conn *pgx.Conn
var DBCtx context.Context

func ConnectDB() {
	dbURL := os.Getenv("DATABASE_URL")
	log.Println(dbURL)

	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		log.Printf("Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	DBCtx = context.Background()
	Conn = conn
	// defer conn.Close(context.Background())

	log.Println("DB Connected")
}
