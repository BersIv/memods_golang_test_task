package main

import (
	"log"
	"memods_golang_test_task/db"
	"memods_golang_test_task/internal/auth"
	"memods_golang_test_task/util"
	"net/http"

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

	log.Println("Database initialized")

	hasher := util.Hasher{}
	tg := util.JWTTokenGetter{}

	authHandler := auth.NewHandler(auth.NewService(auth.NewRepository(dbConn), hasher, tg))

	http.HandleFunc("/getTokens", authHandler.GetTokens)
	http.HandleFunc("/refreshTokens", authHandler.RefreshTokens)

	log.Println("Server started")

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalln("Error listening: ", err)
	}
}
