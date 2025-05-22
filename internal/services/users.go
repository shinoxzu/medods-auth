package services

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/shinoxzu/medods-auth/internal/config"
	"github.com/shinoxzu/medods-auth/internal/errors"
)

type UsersService interface {
	GetMe(token string) (*GetMeResult, error)
}

type DefaultUsersService struct {
	db          *sqlx.DB
	config      *config.SiteConfig
	authService AuthService
}

func NewDefaultUsersService(
	db *sqlx.DB,
	config *config.SiteConfig,
	authService AuthService,
) *DefaultUsersService {
	return &DefaultUsersService{
		db:          db,
		config:      config,
		authService: authService,
	}
}

type GetMeResult struct {
	UserId uuid.UUID
}

func (s *DefaultUsersService) GetMe(token string) (*GetMeResult, error) {
	userID, err := s.authService.ValidateToken(token)
	if err != nil {
		slog.Warn("Failed to validate token", "error", err)
		return nil, fmt.Errorf("%w: cannot validate token error", errors.ErrNotAuthorized)
	}

	return &GetMeResult{UserId: userID}, nil
}
