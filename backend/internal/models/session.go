package models

import (
    "time"
    "gorm.io/gorm"
)

type Session struct {
    gorm.Model
    UserID       uint      `json:"user_id"`
    Token        string    `json:"token" gorm:"uniqueIndex"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresAt    time.Time `json:"expires_at"`
    User         User      `json:"-" gorm:"foreignKey:UserID"`
}