package services

import (
    "context"
    "errors"
    "fmt"
    "github.com/Nerzal/gocloak/v13"
    "github.com/golang-jwt/jwt/v4" // Correct import for the JWT library
    "backend/config"
)

// ConvertJWTToken converts a *jwt.Token to a *gocloak.JWT
func ConvertJWTToken(jwtToken *jwt.Token) *gocloak.JWT {
    if jwtToken == nil {
        return nil
    }

    // Create a new gocloak.JWT object and map fields as needed
    return &gocloak.JWT{
        AccessToken: jwtToken.Raw, // or map specific fields if required
    }
}

type KeycloakService struct {
    client         *gocloak.GoCloak
    microsoftEntra *MicrosoftEntraService
    realm          string
    clientID       string
    clientSecret   string
    config         *config.Config
}

func NewKeycloakService(cfg *config.Config, microsoftEntra *MicrosoftEntraService) *KeycloakService {
    return &KeycloakService{
        client:         gocloak.NewClient(cfg.Keycloak.ServerURL),
        microsoftEntra: microsoftEntra,
        realm:          cfg.Keycloak.Realm,
        clientID:       cfg.Keycloak.ClientID,
        clientSecret:   cfg.Keycloak.ClientSecret,
        config:         cfg,
    }
}

// ValidateToken decodes the JWT token and returns a gocloak.JWT token
func (s *KeycloakService) ValidateToken(ctx context.Context, token string) (*gocloak.JWT, error) {
    // Decode the token using gocloak, which returns three values
    decodedToken, _, err := s.client.DecodeAccessToken(ctx, token, s.realm)
    
    if err != nil {
        return nil, fmt.Errorf("failed to decode token: %w", err)
    }

    if decodedToken == nil {
        return nil, errors.New("decoded token is nil")
    }

    // Convert *jwt.Token to *gocloak.JWT
    convertedToken := ConvertJWTToken(decodedToken)
    if convertedToken == nil {
        return nil, errors.New("failed to convert jwt token to gocloak.JWT")
    }

    // Return the converted gocloak JWT token
    return convertedToken, nil
}

// HandleMicrosoftCallback handles the Microsoft callback, exchanges the code for a token, and manages user creation or fetching in Keycloak
func (s *KeycloakService) HandleMicrosoftCallback(ctx context.Context, code string) (*gocloak.JWT, error) {
    // Get Microsoft token and user info
    microsoftToken, err := s.microsoftEntra.ExchangeCode(ctx, code)
    if err != nil {
        return nil, fmt.Errorf("failed to exchange Microsoft code: %w", err)
    }

    microsoftUser, err := s.microsoftEntra.GetUserInfo(ctx, microsoftToken)
    if err != nil {
        return nil, fmt.Errorf("failed to get Microsoft user info: %w", err)
    }

    // Get admin token for Keycloak operations
    adminToken, err := s.getAdminToken(ctx)
    if err != nil {
        return nil, err
    }

    // Check if user exists in Keycloak
    users, err := s.client.GetUsers(ctx, adminToken, s.realm, gocloak.GetUsersParams{
        Email: &microsoftUser.Mail,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to check existing user: %w", err)
    }

    var userID string
    if len(users) == 0 {
        // Create new user
        user := gocloak.User{
            Email:         &microsoftUser.Mail,
            FirstName:     &microsoftUser.GivenName,
            LastName:      &microsoftUser.Surname,
            EmailVerified: gocloak.BoolP(true),
            Enabled:       gocloak.BoolP(true),
        }

        userID, err = s.client.CreateUser(ctx, adminToken, s.realm, user)
        if err != nil {
            return nil, fmt.Errorf("failed to create user: %w", err)
        }
    } else {
        userID = *users[0].ID
    }

    // Generate Keycloak token
    token, err := s.client.GetToken(ctx, s.realm, gocloak.TokenOptions{
        ClientID:     &s.clientID,
        ClientSecret: &s.clientSecret,
        GrantType:    gocloak.StringP("password"),
        Scope:        gocloak.StringP("openid"),
    })
    if err != nil {
        return nil, fmt.Errorf("failed to get Keycloak token: %w", err)
    }

    return token, nil
}

// getAdminToken fetches the admin token for performing administrative actions in Keycloak
func (s *KeycloakService) getAdminToken(ctx context.Context) (string, error) {
    token, err := s.client.LoginAdmin(ctx, s.config.Keycloak.Admin.Username, s.config.Keycloak.Admin.Password, "master")
    if err != nil {
        return "", fmt.Errorf("failed to get admin token: %w", err)
    }
    return token.AccessToken, nil
}

// RefreshToken refreshes an expired access token using the refresh token
func (s *KeycloakService) RefreshToken(ctx context.Context, refreshToken string) (*gocloak.JWT, error) {
    token, err := s.client.RefreshToken(ctx, refreshToken, s.clientID, s.clientSecret, s.realm)
    if err != nil {
        return nil, fmt.Errorf("failed to refresh token: %w", err)
    }
    return token, nil
}

// Logout logs the user out by invalidating the provided refresh token
func (s *KeycloakService) Logout(ctx context.Context, refreshToken string) error {
    err := s.client.Logout(ctx, s.clientID, s.clientSecret, s.realm, refreshToken)
    if err != nil {
        return fmt.Errorf("failed to logout: %w", err)
    }
    return nil
}
