package database

import (
    "fmt"
    "gorm.io/gorm"
    "gorm.io/driver/postgres"
    "backend/config"
    "backend/internal/models"
)

func InitPostgres(cfg *config.PostgresConfig) (*gorm.DB, error) {
    dsn := fmt.Sprintf(
        "host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
        cfg.Host, cfg.User, cfg.Password, cfg.Name, cfg.Port, cfg.SSLMode,
    )

    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        return nil, err
    }

    sqlDB, err := db.DB()
    if err != nil {
        return nil, err
    }

    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)

    // Auto migrate schemas
    if err := db.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
        return nil, err
    }

    return db, nil
}