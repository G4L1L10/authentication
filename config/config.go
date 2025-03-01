package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// AppConfig holds all configuration settings
type AppConfig struct {
	DatabaseURL string
	JWTSecret   string
	ServerPort  string
	DebugMode   bool
}

var Config *AppConfig

// LoadConfig reads environment variables and initializes Config
func LoadConfig() {
	// Load .env file (if exists)
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system environment variables")
	}

	dbPassword := os.Getenv("DB_PASSWORD")
	databaseURL := os.Getenv("DATABASE_URL")

	// Replace placeholder with actual DB password if it exists
	if dbPassword != "" {
		databaseURL = strings.ReplaceAll(databaseURL, "${DB_PASSWORD}", dbPassword)
	}

	Config = &AppConfig{
		DatabaseURL: databaseURL,
		JWTSecret:   os.Getenv("JWT_SECRET"),
		ServerPort:  os.Getenv("PORT"),
		DebugMode:   os.Getenv("DEBUG_MODE") == "true",
	}

	// Ensure required values exist
	if Config.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required but missing")
	}
	if Config.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required but missing")
	}

	log.Println("✅ Configuration loaded successfully")
}
