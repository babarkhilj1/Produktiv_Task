package services

import (
    "context"
    "errors"
    "fmt"
    "time"
    "gorm.io/gorm"
    "github.com/go-redis/redis/v8"
    "backend/config"
    "backend/internal/models"
)

type SessionService struct {
    db     *gorm.DB
    redis  *redis.Client
    config *config.Config
}

func NewSessionService(db *gorm.DB, redis *redis.Client, config *config.Config) *SessionService {
    return &SessionService{
        db:     db,
        redis:  redis,
        config: config,
    }
}

func (s *SessionService) CreateSession(ctx context.Context, userID uint, token string) (*models.Session, error) {
    session := &models.Session{
        UserID:    userID,
        Token:     token,
        ExpiresAt: time.Now().Add(s.config.Session.TokenExpiry),
    }

    if err := s.db.Create(session).Error; err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    // Cache in Redis
    err := s.redis.Set(ctx,
        fmt.Sprintf("session:%s", token),
        userID,
        s.config.Session.TokenExpiry,
    ).Err()
    if err != nil {
        // Rollback DB creation if Redis fails
        s.db.Delete(session)
        return nil, fmt.Errorf("failed to cache session: %w", err)
    }

    return session, nil
}

func (s *SessionService) GetSession(ctx context.Context, token string) (*models.Session, error) {
    // Try Redis first
    userID, err := s.redis.Get(ctx, fmt.Sprintf("session:%s", token)).Uint64()
    if err == nil {
        var session models.Session
        if err := s.db.Where("token = ? AND user_id = ?", token, userID).First(&session).Error; err != nil {
            return nil, err
        }
        return &session, nil
    }

    // Fallback to database
    var session models.Session
    if err := s.db.Where("token = ?", token).First(&session).Error; err != nil {
        return nil, err
    }

    // Check if expired
    if time.Now().After(session.ExpiresAt) {
        s.DeleteSession(ctx, token)
        return nil, errors.New("session expired")
    }

    // Repopulate Redis
    s.redis.Set(ctx,
        fmt.Sprintf("session:%s", token),
        session.UserID,
        time.Until(session.ExpiresAt),
    )

    return &session, nil
}

func (s *SessionService) DeleteSession(ctx context.Context, token string) error {
    // Delete from Redis
    s.redis.Del(ctx, fmt.Sprintf("session:%s", token))

    // Delete from database
    result := s.db.Where("token = ?", token).Delete(&models.Session{})
    if result.Error != nil {
        return fmt.Errorf("failed to delete session: %w", result.Error)
    }

    if result.RowsAffected == 0 {
        return errors.New("session not found")
    }

    return nil
}

func (s *SessionService) CleanExpiredSessions() error {
    return s.db.Where("expires_at < ?", time.Now()).Delete(&models.Session{}).Error
}

func (s *SessionService) GetUserSessions(ctx context.Context, userID uint) ([]models.Session, error) {
    var sessions []models.Session
    if err := s.db.Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
        return nil, fmt.Errorf("failed to get user sessions: %w", err)
    }
    return sessions, nil
}

func (s *SessionService) DeleteUserSessions(ctx context.Context, userID uint) error {
    // Get all user sessions
    sessions, err := s.GetUserSessions(ctx, userID)
    if err != nil {
        return err
    }

    // Delete from Redis
    for _, session := range sessions {
        s.redis.Del(ctx, fmt.Sprintf("session:%s", session.Token))
    }

    // Delete from database
    result := s.db.Where("user_id = ?", userID).Delete(&models.Session{})
    if result.Error != nil {
        return fmt.Errorf("failed to delete user sessions: %w", result.Error)
    }

    return nil
}
func (s *SessionService) InvalidateSession(ctx context.Context, token string) error {
    // Delete session from Redis
    s.redis.Del(ctx, fmt.Sprintf("session:%s", token))

    // Delete session from the database
    result := s.db.Where("token = ?", token).Delete(&models.Session{})
    if result.Error != nil {
        return fmt.Errorf("failed to invalidate session: %w", result.Error)
    }

    if result.RowsAffected == 0 {
        return errors.New("session not found")
    }

    return nil
}
func (s *SessionService) GetAllSessions(ctx context.Context) ([]models.Session, error) {
    var sessions []models.Session
    if err := s.db.Find(&sessions).Error; err != nil {
        return nil, fmt.Errorf("failed to get all sessions: %w", err)
    }
    return sessions, nil
}
func (s *SessionService) DeleteAllSessions(ctx context.Context) error {
    // Delete all sessions from Redis
    keys, err := s.redis.Keys(ctx, "session:*").Result()
    if err != nil {
        return fmt.Errorf("failed to retrieve keys from Redis: %w", err)
    }
    for _, key := range keys {
        s.redis.Del(ctx, key)
    }

    // Delete all sessions from the database
    if err := s.db.Where("1 = 1").Delete(&models.Session{}).Error; err != nil {
        return fmt.Errorf("failed to delete sessions from the database: %w", err)
    }

    return nil
}
