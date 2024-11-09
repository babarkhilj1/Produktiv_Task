package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email      string    `json:"email" gorm:"uniqueIndex;not null"`
	Name       string    `json:"name"`
	KeycloakID string    `json:"keycloak_id" gorm:"uniqueIndex"`
	LastLogin  time.Time `json:"last_login"`
	Sessions   []Session `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
}
