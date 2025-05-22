package responses

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	apperrors "github.com/shinoxzu/medods-auth/internal/errors"
)

type ErrorResponse struct {
	ErrorCode int    `json:"errorCode"`
	Message   string `json:"message"`
}

type SuccesfullResponse struct {
	Message string `json:"message"`
}

func HandleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apperrors.ErrNotFound):
		HandleError(w, http.StatusNotFound, "Resource not found")
	case errors.Is(err, apperrors.ErrProvidedDataInvalid):
		HandleError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, apperrors.ErrNotAuthorized):
		HandleError(w, http.StatusUnauthorized, "Authentication failed")
	default:
		HandleError(w, http.StatusInternalServerError, "Internal server error")
	}
}

func HandleError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, ErrorResponse{
		ErrorCode: code,
		Message:   message,
	})
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal JSON response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
