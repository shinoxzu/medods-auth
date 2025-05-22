package main

import (
	"log/slog"
	"net/http"
	"os"

	_ "github.com/shinoxzu/medods-auth/docs"
	"github.com/shinoxzu/medods-auth/internal/config"
	"github.com/shinoxzu/medods-auth/internal/controllers"
	"github.com/shinoxzu/medods-auth/internal/services"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Medods Auth API
// @version 1.0
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description Введите токен в формате Bearer {JWT токен}
func main() {
	configureDefaultLogger()

	cfg, err := config.LoadCondig()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	db, err := InitDB(cfg.DatabaseUrl)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	runMigrations(db.DB)

	tokenService := services.NewTokenService(cfg.JwtSigningKey, cfg.JwtExpiresIn)
	authService := services.NewDefaultAuthService(db, cfg, tokenService)
	usersService := services.NewDefaultUsersService(db, cfg, authService)

	authorizeController := controllers.NewAuthorizeController(authService)
	deauthorizeController := controllers.NewDeauthorizeController(authService)
	updateTokensController := controllers.NewUpdateTokensController(authService)
	getMeController := controllers.NewGetMeController(usersService)

	mux := http.NewServeMux()

	controllers.RegisterAuthRoutes(mux, authorizeController, deauthorizeController, updateTokensController)
	controllers.RegisterUsersRoutes(mux, getMeController)

	mux.Handle("/swagger/", httpSwagger.Handler())

	slog.Info("Starting server", "address", cfg.ServerAddr)

	err = http.ListenAndServe(cfg.ServerAddr, mux)
	if err != nil {
		slog.Error("Server error", "error", err)
		os.Exit(1)
	}
}

func configureDefaultLogger() {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(logHandler)
	slog.SetDefault(logger)
}
