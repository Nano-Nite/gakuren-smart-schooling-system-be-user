package main

import (
	"log"

	"gakuren-system.com/pkg/auth"
	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/helper"
	v1 "gakuren-system.com/pkg/route/v1"
)

func main() {
	// Connect to the database
	log.Println("Connecting to the database")
	db.ConnectDB()

	// Run JWT Service
	log.Println("Starting JWT Service")
	if err := auth.NewJWTService(); err != nil {
		log.Fatal(err)
	}

	res, err := auth.HashPassword("wakasek@yopmail.com" + "|" + "ae1368b8-bec5-4a0a-9c4f-dae79a1d5beb" + "|" + "test123")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(res)

	// Setup and launch the Fiber routes
	log.Println("Launching Fiber Routes")
	if "v1" == helper.API_VERSION {
		v1.SetupRoutes()
	}

}
