package services

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinoxzu/medods-auth/internal/errors"
)

type TokenClaims struct {
	SessionId uuid.UUID
	UserId    uuid.UUID
}

type TokenService interface {
	GenerateTokenPair(userID uuid.UUID, sessionID uuid.UUID) (token string, refreshToken []byte, err error)
	ValidateToken(tokenString string) (*TokenClaims, error)
	ValidateTokenSimple(tokenString string) (*TokenClaims, error)
}

type DefaultTokenService struct {
	jwtSecret    []byte
	jwtExpiresIn time.Duration
}

func NewTokenService(jwtSecret []byte, jwtExpiresIn time.Duration) *DefaultTokenService {
	return &DefaultTokenService{
		jwtSecret:    jwtSecret,
		jwtExpiresIn: jwtExpiresIn,
	}
}

func (s *DefaultTokenService) GenerateTokenPair(
	userID uuid.UUID,
	sessionID uuid.UUID,
) (string, []byte, error) {
	token, err := s.generateJWT(userID, sessionID)
	if err != nil {
		slog.Error("Failed to generate JWT token", "error", err)
		return "", nil, fmt.Errorf("%w: could not generate access token", errors.ErrInternal)
	}

	refreshTokenBytes, err := s.generateRefreshToken()
	if err != nil {
		slog.Error("Failed to generate refresh token", "error", err)
		return "", nil, fmt.Errorf("%w: could not generate refresh token", errors.ErrInternal)
	}

	return token, refreshTokenBytes, nil
}

func (s *DefaultTokenService) generateJWT(userID uuid.UUID, sessionID uuid.UUID) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"userId":    userID.String(),
		"sessionId": sessionID.String(),
		"iat":       now.Unix(),
		"exp":       now.Add(s.jwtExpiresIn).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *DefaultTokenService) generateRefreshToken() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *DefaultTokenService) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	}, jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrNotAuthorized, err.Error())
	}
	if !token.Valid {
		return nil, fmt.Errorf("%w: token validation failed", errors.ErrNotAuthorized)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid token claims", errors.ErrNotAuthorized)
	}

	claimsModel, err := mapClaimsToModel(claims)
	if err != nil {
		return nil, fmt.Errorf("%w", errors.ErrInternal)
	}

	return claimsModel, nil
}

func (s *DefaultTokenService) ValidateTokenSimple(tokenString string) (*TokenClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf(
				"%w: unexpected signing method: %v",
				errors.ErrNotAuthorized,
				token.Header["alg"],
			)
		}
		if token.Method != jwt.SigningMethodHS512 {
			return nil, fmt.Errorf("%w: invalid algorithm", errors.ErrNotAuthorized)
		}

		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrNotAuthorized, err.Error())
	}
	if !token.Valid {
		return nil, fmt.Errorf("%w: token validation failed", errors.ErrNotAuthorized)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid token claims", errors.ErrNotAuthorized)
	}

	claimsModel, err := mapClaimsToModel(claims)
	if err != nil {
		return nil, fmt.Errorf("%w", errors.ErrInternal)
	}

	return claimsModel, nil
}

func mapClaimsToModel(claims jwt.MapClaims) (*TokenClaims, error) {
	userIdStr, ok := claims["userId"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing user ID in token", errors.ErrNotAuthorized)
	}
	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user ID format", errors.ErrNotAuthorized)
	}

	sessionIdStr, ok := claims["sessionId"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing session ID in token", errors.ErrNotAuthorized)
	}
	sessionId, err := uuid.Parse(sessionIdStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid session ID format", errors.ErrNotAuthorized)
	}

	return &TokenClaims{
		SessionId: sessionId,
		UserId:    userId,
	}, nil
}
