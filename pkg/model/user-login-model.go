package model

import (
	"time"

	"github.com/google/uuid"
)

type UserLoginModel struct {
	UUID          uuid.UUID  `db:"uuid"`
	UserUUID      uuid.UUID  `db:"user_uuid"`
	Username      string     `db:"username"`
	Password      string     `db:"password"`
	LastLogin     time.Time  `db:"last_login"`
	LastLogout    *time.Time `db:"last_logout"`
	FailedAttempt int        `db:"failed_attempt"`
	StatusUUID    uuid.UUID  `db:"status_uuid"`
	CreatedDate   time.Time  `db:"created_date"`
	UpdatedDate   *time.Time `db:"updated_date"`
}
