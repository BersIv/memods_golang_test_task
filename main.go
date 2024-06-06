package main

import (
	"fmt"
	"log"
	"memods_golang_test_task/db"

	"github.com/joho/godotenv"
)

func main() {
	log.Println("Server is starting")
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env: ", err)
	}

	dbConn, err := db.NewDatabase()
	if err != nil {
		log.Fatalln("Error creating database connection: ", err)
	}
	defer dbConn.Close()

	

	fmt.Println(dbConn)
}
