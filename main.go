package main

import (
	"log"

	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/route"
)

func main() {
	// Connect to the database
	log.Println("Connecting to the database")
	db.ConnectDB()

	// Setup and launch the Fiber routes
	log.Println("Launching Fiber Routes")
	route.SetupRoutes()

}
