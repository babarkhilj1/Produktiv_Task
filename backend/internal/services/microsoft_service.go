// package services

// import (
//     "context"
//     "encoding/json"
//     "fmt"
//     "net/http"
//     "golang.org/x/oauth2"
//     "golang.org/x/oauth2/microsoft"
//     "backend/config"
// )

// type MicrosoftUser struct {
//     ID                string `json:"id"`
//     DisplayName       string `json:"displayName"`
//     GivenName        string `json:"givenName"`
//     Surname          string `json:"surname"`
//     UserPrincipalName string `json:"userPrincipalName"`
//     Mail             string `json:"mail"`
// }

// type MicrosoftEntraService struct {
//     config     *oauth2.Config
//     httpClient *http.Client
// }

// func NewMicrosoftEntraService(cfg *config.Config) *MicrosoftEntraService {
//     oauth2Config := &oauth2.Config{
//         ClientID:     cfg.Microsoft.ClientID,
//         ClientSecret: cfg.Microsoft.ClientSecret,
//         RedirectURL:  cfg.Microsoft.RedirectURI,
//         Scopes:       cfg.Microsoft.Scopes,
//         Endpoint:     microsoft.AzureADEndpoint(cfg.Microsoft.TenantID),
//     }

//     return &MicrosoftEntraService{
//         config:     oauth2Config,
//         httpClient: &http.Client{},
//     }
// }

// func (s *MicrosoftEntraService) GetAuthURL() string {
//     return s.config.AuthCodeURL("state")
// }

// func (s *MicrosoftEntraService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
//     token, err := s.config.Exchange(ctx, code)
//     if err != nil {
//         return nil, fmt.Errorf("failed to exchange code: %w", err)
//     }
//     return token, nil
// }

// func (s *MicrosoftEntraService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*MicrosoftUser, error) {
//     client := s.config.Client(ctx, token)
//     resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
//     if err != nil {
//         return nil, fmt.Errorf("failed to get user info: %w", err)
//     }
//     defer resp.Body.Close()

//     if resp.StatusCode != http.StatusOK {
//         return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
//     }

//     var user MicrosoftUser
//     if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
//         return nil, fmt.Errorf("failed to decode user info: %w", err)
//     }

//     return &user, nil
// }

// func (s *MicrosoftEntraService) ValidateToken(token *oauth2.Token) bool {
//     return token.Valid()
// 
package services

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/microsoft"
    "backend/config"
)

// MicrosoftUser contains user information retrieved via OpenID Connect
type MicrosoftUser struct {
    ID                string `json:"id"`
    DisplayName       string `json:"displayName"`
    GivenName         string `json:"givenName"`
    Surname           string `json:"surname"`
    UserPrincipalName string `json:"userPrincipalName"`
    Mail              string `json:"mail"`
}

// MicrosoftEntraService handles interactions with Microsoft Entra using OpenID Connect
type MicrosoftEntraService struct {
    config     *oauth2.Config
    httpClient *http.Client
}

func NewMicrosoftEntraService(cfg *config.Config) *MicrosoftEntraService {
    return &MicrosoftEntraService{
        config: &oauth2.Config{
            ClientID:     cfg.Microsoft.ClientID,
            ClientSecret: cfg.Microsoft.ClientSecret,
            RedirectURL:  cfg.Microsoft.RedirectURI,
            Scopes:       []string{"openid", "profile", "email"}, // Add OpenID scope
            Endpoint:     microsoft.AzureADEndpoint(cfg.Microsoft.TenantID),
        },
        httpClient: &http.Client{},
    }
}

func (s *MicrosoftEntraService) GetAuthURL(state string) string {
    return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *MicrosoftEntraService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
    token, err := s.config.Exchange(ctx, code)
    if err != nil {
        return nil, fmt.Errorf("failed to exchange code: %w", err)
    }
    return token, nil
}

func (s *MicrosoftEntraService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*MicrosoftUser, error) {
    client := s.config.Client(ctx, token)
    resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
    if err != nil {
        return nil, fmt.Errorf("failed to get user info: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
    }

    var user MicrosoftUser
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, fmt.Errorf("failed to decode user info: %w", err)
    }

    return &user, nil
}
// RefreshAccessToken refreshes the access token using the provided refresh token
func (s *MicrosoftEntraService) RefreshAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
    // Create a new token using the refresh token
    token := &oauth2.Token{
        RefreshToken: refreshToken,
    }

    // Use the token source to refresh the access token
    tokenSource := s.config.TokenSource(ctx, token)
    newToken, err := tokenSource.Token()
    if err != nil {
        return nil, fmt.Errorf("failed to refresh token: %w", err)
    }

    return newToken, nil
}//built by DPS
