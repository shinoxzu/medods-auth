package controllers

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/shinoxzu/medods-auth/internal/responses"
	"github.com/shinoxzu/medods-auth/internal/services"
)

func RegisterAuthRoutes(
	mux *http.ServeMux,
	authorizeHandler func(w http.ResponseWriter, r *http.Request),
	deauthorizeHandler func(w http.ResponseWriter, r *http.Request),
	updateHandler func(w http.ResponseWriter, r *http.Request),
) {
	mux.HandleFunc("POST /auth", authorizeHandler)
	mux.HandleFunc("POST /deauth", deauthorizeHandler)
	mux.HandleFunc("POST /refresh", updateHandler)
}

type AuthorizeResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// @Summary Получить новую пару токенов для указанного userId
// @Tags auth
// @Produce json
// @Param userId query string true "UUID пользователя" example("123e4567-e89b-12d3-a456-426614174000")
// @Success 200 {object} AuthorizeResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /auth [post]
func NewAuthorizeController(
	authService services.AuthService,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		userIdRaw := r.URL.Query().Get("userId")
		userId, err := uuid.Parse(userIdRaw)
		if err != nil {
			slog.Warn("Invalid user ID format", "userIdRaw", userIdRaw)
			responses.HandleError(w, http.StatusBadRequest, "Invalid user ID format")
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		result, err := authService.Authorize(userId, ip, r.Header.Get("User-Agent"))
		if err != nil {
			responses.HandleServiceError(w, err)
			return
		}

		response := AuthorizeResponse{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
		}
		responses.RespondWithJSON(w, http.StatusOK, response)
	}
}

// @Summary Деавторизоваться
// @Tags auth
// @Produce json
// @Security ApiKeyAuth
// @Param Authorization header string true "JWT-токен в формате Bearer {token}"
// @Success 200 {object} responses.SuccesfullResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /deauth [post]
func NewDeauthorizeController(
	authService services.AuthService,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		err := authService.Deauthorize(token)
		if err != nil {
			responses.HandleServiceError(w, err)
			return
		}

		response := responses.SuccesfullResponse{
			Message: "ok!",
		}
		responses.RespondWithJSON(
			w,
			http.StatusOK,
			response,
		)
	}
}

type RefreshRequest struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// @Summary Обновить токены
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Данные для обновления токенов"
// @Success 200 {object} AuthorizeResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /refresh [post]
func NewUpdateTokensController(
	authService services.AuthService,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			responses.HandleError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		result, err := authService.Update(
			req.AccessToken,
			req.RefreshToken,
			ip,
			r.Header.Get("User-Agent"),
		)
		if err != nil {
			responses.HandleServiceError(w, err)
			return
		}

		response := AuthorizeResponse{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
		}
		responses.RespondWithJSON(w, http.StatusOK, response)
	}
}
