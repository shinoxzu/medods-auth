package models

import (
	"github.com/google/uuid"
)

type Session struct {
	Id           uuid.UUID `db:"id"`
	UserId       uuid.UUID `db:"user_id"`
	RefreshToken []byte    `db:"refresh_token"`
	UserAgent    string    `db:"user_agent"`
	IpAddress    string    `db:"ip_address"`
}
