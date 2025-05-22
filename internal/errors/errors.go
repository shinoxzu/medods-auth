package errors

import (
	"errors"
)

var (
	ErrProvidedDataInvalid = errors.New("provided data is invalid")
	ErrInternal            = errors.New("internal server error")
	ErrNotFound            = errors.New("not found")
	ErrNotAuthorized       = errors.New("not authorized")
)
