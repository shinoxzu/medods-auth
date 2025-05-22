package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type SiteConfig struct {
	DatabaseUrl   string
	JwtSigningKey []byte
	NewIpWebhook  string
	ServerAddr    string
	JwtExpiresIn  time.Duration
}

func LoadCondig() (*SiteConfig, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	return &SiteConfig{
		DatabaseUrl:   os.Getenv("DATABASE_URL"),
		JwtSigningKey: []byte(os.Getenv("JWT_SIGNING_KEY")),
		NewIpWebhook:  os.Getenv("NEW_IP_WEBHOOK"),
		ServerAddr:    os.Getenv("SERVER_ADDR"),
		JwtExpiresIn:  time.Minute * 5,
	}, nil
}
