package controllers

import (
	"net/http"
	"strings"

	"github.com/shinoxzu/medods-auth/internal/responses"
	"github.com/shinoxzu/medods-auth/internal/services"
)

func RegisterUsersRoutes(
	mux *http.ServeMux,
	getMeHandler func(w http.ResponseWriter, r *http.Request),
) {
	mux.HandleFunc("GET /users/me", getMeHandler)
}

type GetMeResponse struct {
	UserId string `json:"userId"`
}

// @Summary Получить информацию о себе
// @Tags users
// @Produce json
// @Security ApiKeyAuth
// @Param Authorization header string true "JWT-токен в формате Bearer {token}"
// @Success 200 {object} GetMeResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/me [get]
func NewGetMeController(
	usersService services.UsersService,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		me, err := usersService.GetMe(token)
		if err != nil {
			responses.HandleServiceError(w, err)
			return
		}

		response := GetMeResponse{
			UserId: me.UserId.String(),
		}
		responses.RespondWithJSON(w, http.StatusOK, response)
	}
}
