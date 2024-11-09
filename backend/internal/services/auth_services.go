package services

import (
    "context"
    "errors"
    "fmt"
    "time"
    
    "gorm.io/gorm"
    "github.com/go-redis/redis/v8"
    "go.uber.org/zap"
    "github.com/golang-jwt/jwt/v4"
    "backend/config"
    "backend/internal/models"
    "github.com/spf13/viper"
)

var (
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrUserNotFound      = errors.New("user not found")
    ErrSessionExpired    = errors.New("session expired")
)

type AuthService struct {
    db             *gorm.DB
    redis          *redis.Client
    keycloak       *KeycloakService
    microsoftEntra *MicrosoftEntraService
    config         *config.Config
    logger         *zap.Logger
}
func LoadConfig() error {
    // Specify the config file location
    viper.SetConfigName("config")      // Config file name without extension
    viper.SetConfigType("yaml")        // File format (YAML)
    viper.AddConfigPath("./backend/config")  // Path to your config folder

    // Attempt to read in the configuration
    if err := viper.ReadInConfig(); err != nil {
        return fmt.Errorf("error reading config file: %w", err)
    }
    return nil
}
func NewAuthService(
    db *gorm.DB,
    redis *redis.Client,
    keycloak *KeycloakService,
    microsoftEntra *MicrosoftEntraService,
    config *config.Config,
    logger *zap.Logger,
) *AuthService {
    return &AuthService{
        db:             db,
        redis:          redis,
        keycloak:       keycloak,
        microsoftEntra: microsoftEntra,
        config:         config,
        logger:         logger,
    }
}
// UpdateUser updates the user details in the database
func (s *AuthService) UpdateUser(ctx context.Context, user *models.User, updates map[string]interface{}) error {
    // Ensure that updates are not nil or empty
    if len(updates) == 0 {
        return errors.New("no updates provided")
    }

    // Update the user record in the database
    err := s.db.Model(user).Updates(updates).Error
    if err != nil {
        s.logger.Error("Failed to update user", zap.Error(err))
        return fmt.Errorf("failed to update user: %w", err)
    }

    return nil
}//built by DPS
// InitiateAuth starts the authentication process
func (s *AuthService) InitiateAuth(ctx context.Context, redirectURI string) (string, error) {
    // Start with Keycloak which will handle Microsoft authentication
    authURL := s.keycloak.HandleMicrosoftLogin(ctx,redirectURI)
    return authURL, nil
}
// GetLoginURL provides the login URL for the authentication process (if you prefer this method)
func (s *AuthService) GetLoginURL(ctx context.Context, redirectURI string) (string, error) {
    return s.InitiateAuth(ctx, redirectURI)
}//built by DPS


// ValidateIDToken validates an ID token (JWT) for authenticity and expiration
func (s *AuthService) ValidateIDToken(ctx context.Context, idToken string) (*jwt.Token, error) {
    // The secret key or public key used to validate the token
    // (This should be fetched from a secure location or Keycloak configuration)
    secretKey := s.config.KeycloakSecretKey

    // Parse the token and validate its signature and claims
    token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return secretKey, nil
    })

    if err != nil {
        s.logger.Error("Failed to validate ID token", zap.Error(err))
        return nil, ErrInvalidToken
    }

    // Ensure the token is valid and not expired
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        if exp, ok := claims["exp"].(float64); ok {
            // Check if the token is expired
            if time.Unix(int64(exp), 0).Before(time.Now()) {
                return nil, ErrSessionExpired
            }
        }
    } else {
        return nil, ErrInvalidToken
    }

    return token, nil
}//Built by DPS

// HandleCallback processes the authentication callback
func (s *AuthService) HandleCallback(ctx context.Context, code, redirectURI string) (*models.User, string, error) {
    // Get tokens and user info from Keycloak
    token, err := s.keycloak.HandleMicrosoftCallback(ctx, code)
    if err != nil {
        s.logger.Error("Failed to handle callback", zap.Error(err))
        return nil, "", err
    }

    // Find or create local user
    user, err := s.findOrCreateUser(ctx, keycloakUser)
    if err != nil {
        s.logger.Error("Failed to find or create user", zap.Error(err))
        return nil, "", err
    }

    // Create session in Redis
    sessionToken := token.AccessToken
    err = s.redis.Set(ctx,
        fmt.Sprintf("session:%s", sessionToken),
        user.ID,
        time.Duration(token.ExpiresIn)*time.Second,
    ).Err()
    if err != nil {
        s.logger.Error("Failed to create session", zap.Error(err))
        return nil, "", fmt.Errorf("failed to create session: %w", err)
    }

    return user, sessionToken, nil
}

// ValidateSession validates the current session
func (s *AuthService) ValidateSession(ctx context.Context, token string) (*models.User, error) {
    // Validate token with Keycloak
    _, err := s.keycloak.ValidateToken(ctx, token)
    if err != nil {
        s.logger.Error("Token validation failed", zap.Error(err))
        return nil, ErrSessionExpired
    }

    // Get user ID from Redis
    userID, err := s.redis.Get(ctx, fmt.Sprintf("session:%s", token)).Uint64()
    if err != nil {
        s.logger.Error("Session not found in Redis", zap.Error(err))
        return nil, ErrSessionExpired
    }

    // Get user from database
    var user models.User
    if err := s.db.First(&user, userID).Error; err != nil {
        s.logger.Error("User not found in database", zap.Error(err))
        return nil, ErrUserNotFound
    }

    return &user, nil
}

// Logout handles user logout
func (s *AuthService) Logout(ctx context.Context, token string) error {
    // Logout from Keycloak
    if err := s.keycloak.Logout(ctx, token); err != nil {
        s.logger.Error("Failed to logout from Keycloak", zap.Error(err))
        return err
    }

    // Remove session from Redis
    if err := s.redis.Del(ctx, fmt.Sprintf("session:%s", token)).Err(); err != nil {
        s.logger.Error("Failed to remove session from Redis", zap.Error(err))
        return err
    }

    return nil
}

// RefreshSession refreshes the current session
func (s *AuthService) RefreshSession(ctx context.Context, refreshToken string) (string, error) {
    // Refresh token in Keycloak
    newToken, err := s.keycloak.RefreshToken(ctx, refreshToken)
    if err != nil {
        s.logger.Error("Failed to refresh token", zap.Error(err))
        return "", err
    }

    // Update session in Redis
    sessionKey := fmt.Sprintf("session:%s", newToken.AccessToken)
    userID, err := s.redis.Get(ctx, fmt.Sprintf("session:%s", refreshToken)).Uint64()
    if err != nil {
        s.logger.Error("Failed to get user ID from Redis", zap.Error(err))
        return "", err
    }

    err = s.redis.Set(ctx,
        sessionKey,
        userID,
        time.Duration(newToken.ExpiresIn)*time.Second,
    ).Err()
    if err != nil {
        s.logger.Error("Failed to update session in Redis", zap.Error(err))
        return "", err
    }

    // Delete old session
    s.redis.Del(ctx, fmt.Sprintf("session:%s", refreshToken))

    return newToken.AccessToken, nil
}

// Helper functions

func (s *AuthService) findOrCreateUser(ctx context.Context, keycloakUser *KeycloakUser) (*models.User, error) {
    var user models.User
    
    // Try to find existing user
    err := s.db.Where("keycloak_id = ?", keycloakUser.ID).First(&user).Error
    if err == nil {
        // Update user information
        user.Email = keycloakUser.Email
        user.Name = fmt.Sprintf("%s %s", keycloakUser.FirstName, keycloakUser.LastName)
        user.LastLogin = time.Now()
        
        if err := s.db.Save(&user).Error; err != nil {
            return nil, fmt.Errorf("failed to update user: %w", err)
        }
        
        return &user, nil
    }

    // Create new user if not found
    if errors.Is(err, gorm.ErrRecordNotFound) {
        user = models.User{
            Email:      keycloakUser.Email,
            Name:       fmt.Sprintf("%s %s", keycloakUser.FirstName, keycloakUser.LastName),
            KeycloakID: keycloakUser.ID,
            LastLogin:  time.Now(),
        }
        
        if err := s.db.Create(&user).Error; err != nil {
            return nil, fmt.Errorf("failed to create user: %w", err)
        }
        
        return &user, nil
    }

    return nil, fmt.Errorf("failed to find or create user: %w", err)
}
// GetUserFromToken retrieves user information from a token
func (s *AuthService) GetUserFromToken(ctx context.Context, token string) (*models.User, error) {
    // Validate the token (you might already have this logic in another method)
    _, err := s.keycloak.ValidateToken(ctx, token)
    if err != nil {
        s.logger.Error("Token validation failed", zap.Error(err))
        return nil, ErrInvalidToken
    }

    // Retrieve user ID from Redis or database using the token
    userID, err := s.redis.Get(ctx, fmt.Sprintf("session:%s", token)).Uint64()
    if err != nil {
        s.logger.Error("Session not found in Redis", zap.Error(err))
        return nil, ErrSessionExpired
    }

    // Fetch the user from the database
    var user models.User
    if err := s.db.First(&user, userID).Error; err != nil {
        s.logger.Error("User not found in database", zap.Error(err))
        return nil, ErrUserNotFound
    }

    return &user, nil
}
// // ValidateToken validates the given token and returns a user if the token is valid.
// func (a *AuthService) ValidateToken(ctx context.Context, tokenString string) (*models.User, error) {
//     // Define your secret key
//     secretKey := "your-SECRET-key"

//     // Parse the token
//     token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//         // Check the signing method
//         if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
//             return nil, errors.New("unexpected signing method")
//         }
//         return []byte(secretKey), nil
//     })

//     // Handle token parsing errors
//     if err != nil || !token.Valid {
//         return nil, errors.New("invalid token")
//     }

//     // Extract claims (if needed)
//     if claims, ok := token.Claims.(jwt.MapClaims); ok {
//         userID := claims["user_id"].(string) // Assuming `user_id` is in your token claims
        
//         // Fetch the user (assuming a user-fetching mechanism)
//         user := &models.User{}
//         if err := FetchUserFromDatabaseByID(userID, user); err != nil {
//             return nil, errors.New("user not found")
//         }

//         return user, nil
//     }

//     return nil, errors.New("invalid token claims")
// }

func (a *AuthService) ValidateToken(ctx context.Context, tokenString string) (*models.User, error) {
    // Load the config to get values like client_secret
    if err := LoadConfig(); err != nil {
        return nil, fmt.Errorf("failed to load configuration: %v", err)
    }

    // Get the client_id or any other necessary values
    clientID := viper.GetString("microsoft.client_id")
    if clientID == "" {
        return nil, errors.New("client_id not found in configuration")
    }

    // Use the retrieved client_id or secretKey for your token validation
    secretKey := clientID  // You can use the clientID here or modify this as per your logic

    // Parse the token with the clientID as the secret key
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Ensure the signing method is HMAC
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(secretKey), nil
    })

    if err != nil || !token.Valid {
        return nil, errors.New("invalid token")
    }

    // Extract claims (user_id in this case)
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        userID := claims["user_id"].(string) // Assuming `user_id` exists in your token

        // Fetch user from database or any other source
        user := &models.User{}
        if err := FetchUserFromDatabaseByID(userID, user); err != nil {
            return nil, errors.New("user not found")
        }

        return user, nil
    }

    return nil, errors.New("invalid token claims")
}




