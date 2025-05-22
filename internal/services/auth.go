package services

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/shinoxzu/medods-auth/internal/config"
	"github.com/shinoxzu/medods-auth/internal/errors"
	"github.com/shinoxzu/medods-auth/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Authorize(userId uuid.UUID, ipAddress string, userAgent string) (*AuthorizeResult, error)
	Deauthorize(token string) error
	Update(token string, refreshToken string, ipAddress string, userAgent string) (*AuthorizeResult, error)
	ValidateToken(token string) (uuid.UUID, error)
}

type DefaultAuthService struct {
	db           *sqlx.DB
	config       *config.SiteConfig
	tokenService TokenService
}

func NewDefaultAuthService(
	db *sqlx.DB,
	config *config.SiteConfig,
	tokenService TokenService,
) *DefaultAuthService {
	return &DefaultAuthService{
		db:           db,
		config:       config,
		tokenService: tokenService,
	}
}

type AuthorizeResult struct {
	Token        string
	RefreshToken string
}

func (s *DefaultAuthService) Authorize(
	userId uuid.UUID,
	ipAddress string,
	userAgent string,
) (*AuthorizeResult, error) {
	transaction, err := s.db.Beginx()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}
	defer transaction.Rollback()

	sessionId := uuid.New()

	token, refreshToken, err := s.tokenService.GenerateTokenPair(userId, sessionId)
	if err != nil {
		slog.Error("Failed to generate tokens", "userId", userId, "error", err)
		return nil, err
	}

	hashedRefreshToken, err := bcrypt.GenerateFromPassword(refreshToken, bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Failed to hash refresh token", "error", err)
		return nil, fmt.Errorf("%w: could not process token", errors.ErrInternal)
	}

	session := models.Session{
		Id:           sessionId,
		UserId:       userId,
		RefreshToken: hashedRefreshToken,
		UserAgent:    userAgent,
		IpAddress:    ipAddress,
	}

	_, err = transaction.NamedExec(`
		INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip_address)
		VALUES (:id, :user_id, :refresh_token, :user_agent, :ip_address)
	`, session)

	if err != nil {
		slog.Error("Failed to insert session", "userId", userId, "error", err)
		return nil, fmt.Errorf("%w: could not create session", errors.ErrInternal)
	}

	err = transaction.Commit()
	if err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	slog.Info("User authorized", "userId", userId)

	return &AuthorizeResult{
		Token:        token,
		RefreshToken: base64.StdEncoding.EncodeToString(refreshToken),
	}, nil
}

func (s *DefaultAuthService) Deauthorize(token string) error {
	claims, err := s.tokenService.ValidateToken(token)
	if err != nil {
		slog.Warn("Invalid token during deauthorization", "error", err)
		return fmt.Errorf("%w: invalid access token", errors.ErrNotAuthorized)
	}

	transaction, err := s.db.Beginx()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return fmt.Errorf("%w: database error", errors.ErrInternal)
	}
	defer transaction.Rollback()

	// we don`t care about count of deleted rows i suppose
	_, err = transaction.Exec("DELETE FROM sessions WHERE id = $1", claims.SessionId)
	if err != nil {
		slog.Error("Failed to delete session", "sessionId", claims.SessionId, "error", err)
		return fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	err = transaction.Commit()
	if err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	slog.Info("User deauthorized", "userId", claims.UserId, "sessionId", claims.SessionId)

	return nil
}

func (s *DefaultAuthService) Update(
	token string,
	refreshTokenBase64 string,
	ipAddress string,
	userAgent string,
) (*AuthorizeResult, error) {
	// tokens is likely expired here so we allow it
	claims, err := s.tokenService.ValidateTokenSimple(token)
	if err != nil {
		slog.Warn("Invalid token pair during refresh", "error", err)
		return nil, err
	}

	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenBase64)
	if err != nil {
		slog.Warn("Failed to decode refresh token", "error", err)
		return nil, fmt.Errorf("%w: invalid refresh token format", errors.ErrProvidedDataInvalid)
	}

	transaction, err := s.db.Beginx()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}
	defer transaction.Rollback()

	var session models.Session
	err = transaction.Get(&session, "SELECT * FROM sessions WHERE id = $1", claims.SessionId)
	if err != nil {
		slog.Warn("Session not found", "sessionId", claims.SessionId, "error", err)
		return nil, fmt.Errorf("%w: session not found", errors.ErrNotAuthorized)
	}

	err = bcrypt.CompareHashAndPassword(session.RefreshToken, refreshToken)
	if err != nil {
		slog.Warn("Invalid refresh token", "sessionId", claims.SessionId, "error", err)
		return nil, fmt.Errorf("%w: invalid refresh token", errors.ErrNotAuthorized)
	}

	if session.UserAgent != userAgent {
		slog.Warn(
			"User-Agent mismatch",
			"sessionId", claims.SessionId,
			"expected", session.UserAgent,
			"actual", userAgent,
		)

		_, err = transaction.Exec("DELETE FROM sessions WHERE session_id = $1", session.Id)
		if err != nil {
			slog.Error("Failed to delete session", "userId", session.UserId, "error", err)
		}

		err = transaction.Commit()
		if err != nil {
			slog.Error("Failed to commit transaction", "error", err)
		}

		return nil, fmt.Errorf("%w: User-Agent mismatch", errors.ErrNotAuthorized)
	}

	if session.IpAddress != ipAddress {
		slog.Info(
			"IP address changed",
			"userId", session.UserId,
			"oldIP", session.IpAddress,
			"newIP", ipAddress,
		)

		err = s.NotifyAboutNewIp(session.UserId, session.IpAddress, ipAddress)
		if err != nil {
			slog.Error("Failed to notify about IP change", "error", err)
		}

		session.IpAddress = ipAddress
	}

	newToken, newRefreshToken, err := s.tokenService.GenerateTokenPair(session.UserId, session.Id)
	if err != nil {
		slog.Error("Failed to generate new tokens", "userId", session.UserId, "error", err)
		return nil, err
	}

	hashedRefreshToken, err := bcrypt.GenerateFromPassword(newRefreshToken, bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Failed to hash refresh token", "error", err)
		return nil, fmt.Errorf("%w: could not process token", errors.ErrInternal)
	}

	_, err = transaction.Exec(
		"UPDATE sessions SET refresh_token = $1, ip_address = $2 WHERE id = $3",
		hashedRefreshToken, ipAddress, session.Id,
	)
	if err != nil {
		slog.Error("Failed to update session", "sessionId", session.Id, "error", err)
		return nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	err = transaction.Commit()
	if err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	slog.Info("Tokens refreshed", "userId", session.UserId, "sessionId", session.Id)

	return &AuthorizeResult{
		Token:        newToken,
		RefreshToken: base64.StdEncoding.EncodeToString(newRefreshToken),
	}, nil
}

func (s *DefaultAuthService) ValidateToken(token string) (uuid.UUID, error) {
	claims, err := s.tokenService.ValidateToken(token)
	if err != nil {
		return uuid.Nil, err
	}

	var count int
	err = s.db.Get(&count, "SELECT COUNT(*) FROM sessions WHERE id = $1", claims.SessionId)
	if err != nil {
		slog.Error("Failed to check session", "sessionId", claims.SessionId, "error", err)
		return uuid.Nil, fmt.Errorf("%w: database error", errors.ErrInternal)
	}

	if count == 0 {
		return uuid.Nil, fmt.Errorf("%w: session not found", errors.ErrNotAuthorized)
	}

	return claims.UserId, nil
}

func (s *DefaultAuthService) NotifyAboutNewIp(userID uuid.UUID, oldIP string, newIP string) error {
	slog.Info(
		"Notifying webhook about IP change",
		"webhook", s.config.NewIpWebhook,
		"user", userID,
		"oldIP", oldIP,
		"newIP", newIP,
	)

	body, _ := json.Marshal(map[string]string{
		"userId": userID.String(),
		"oldIp":  oldIP,
		"newIp":  newIP,
	})

	resp, err := http.Post(s.config.NewIpWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook post failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
