package controllers

import (
    "strconv"
    "context"
    "net/http"
    
    "github.com/gin-gonic/gin"
    "backend/internal/services"
    // "go.uber.org/zap" // Import the zap logging package
)

type AuthController struct {
    authService      *services.AuthService
    sessionService   *services.SessionService
    microsoftService *services.MicrosoftEntraService
}

func NewAuthController(authService *services.AuthService, sessionService *services.SessionService, microsoftService *services.MicrosoftEntraService) *AuthController {
    return &AuthController{
        authService:      authService,
        sessionService:   sessionService,
        microsoftService: microsoftService,
    }
}

// InitiateMicrosoftLogin initiates the OpenID Connect login with Microsoft
func (c *AuthController) InitiateMicrosoftLogin(ctx *gin.Context) {
    state := "some-random-state" // This should be dynamically generated and validated in production
    authURL := c.microsoftService.GetAuthURL(state)
    ctx.Redirect(http.StatusFound, authURL)
}

// HandleMicrosoftCallback handles the callback from Microsoft after OpenID Connect login
func (c *AuthController) HandleMicrosoftCallback(ctx *gin.Context) {
    code := ctx.Query("code")
    state := ctx.Query("state") // Optionally validate state if you use one

    if code == "" {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Authorization code is missing"})
        return
    }

    // Exchange the authorization code for an access token and ID token
    token, err := c.microsoftService.ExchangeCode(context.Background(), code)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code: " + err.Error()})
        return
    }

    // Get user information from the token using OpenID Connect
    user, err := c.microsoftService.GetUserInfo(context.Background(), token)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user info: " + err.Error()})
        return
    }

    // Convert user.ID from string to uint
    userID, err := strconv.ParseUint(user.ID, 10, 64)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to convert user ID: " + err.Error()})
        return
    }

    // Example of handling user data and creating a session
    session, err := c.sessionService.CreateSession(ctx, uint(userID), token.AccessToken)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session: " + err.Error()})
        return
    }

    ctx.JSON(http.StatusOK, gin.H{
        "user":    user,
        "token":   token.AccessToken,
        "expires": session.ExpiresAt,
    })
}
// InitiateLogin starts the OpenID Connect login process
func (c *AuthController) InitiateLogin(ctx *gin.Context) {
    // Get the OpenID Connect login URL from AuthService
    loginURL := c.authService.GetLoginURL()

    // Redirect the user to the login page of the identity provider
    ctx.Redirect(http.StatusFound, loginURL)
}


// HandleCallback handles the callback after OpenID Connect login
func (c *AuthController) HandleCallback(ctx *gin.Context) {
    // Retrieve the ID token and state from the callback parameters
    idToken := ctx.DefaultQuery("id_token", "")
    state := ctx.DefaultQuery("state", "")

    if idToken == "" {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "ID token is missing"})
        return
    }

    // Validate the ID token (signature, nonce, etc.)
    user, err := c.authService.ValidateIDToken(idToken, state)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate ID token: " + err.Error()})
        return
    }

    // Create a session with the user info
    session, err := c.sessionService.CreateSession(ctx, user.ID, idToken)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session: " + err.Error()})
        return
    }

    // Respond with user info and session details
    ctx.JSON(http.StatusOK, gin.H{
        "user":    user,
        "expires": session.ExpiresAt,
    })
}
// ValidateToken validates the token using the AuthService
func (c *AuthController) ValidateToken(ctx *gin.Context) {
    token := ctx.DefaultQuery("id_token", "")
    if token == "" {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "ID token is missing"})
        return
    }

    // Call the ValidateToken method in the AuthService to validate the token
    user, err := c.authService.ValidateIDToken(token)
    if err != nil {
        ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
        return
    }

    // Return the user information if token is valid
    ctx.JSON(http.StatusOK, gin.H{
        "user": user,
    })
}
// RefreshToken refreshes the user's access token using the refresh token
func (c *AuthController) RefreshToken(ctx *gin.Context) {
    refreshToken := ctx.DefaultQuery("refresh_token", "")
    if refreshToken == "" {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is missing"})
        return
    }

    // Use the refresh token to get a new access token (this will depend on the OpenID provider)
    newToken, err := c.microsoftService.RefreshAccessToken(refreshToken)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token: " + err.Error()})
        return
    }

    ctx.JSON(http.StatusOK, gin.H{
        "new_token": newToken.AccessToken,
        "expires_in": newToken.ExpiresIn,
    })
}
// Logout handles logging the user out by invalidating the session
func (c *AuthController) Logout(ctx *gin.Context) {
    // Get the current session, e.g., from a cookie or header
    sessionID := ctx.GetHeader("Session-ID")
    if sessionID == "" {
        ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Session ID is missing"})
        return
    }

    // Invalidate the session using the session service
    err := c.sessionService.InvalidateSession(ctx, sessionID)//built by DPS 
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to invalidate session: " + err.Error()})
        return
    }

    // Optionally, clear any authentication cookies or tokens
    ctx.SetCookie("session_token", "", -1, "/", "", false, true)

    // Respond with a success message
    ctx.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
// GetCurrentUser gets the current authenticated user
func (c *AuthController) GetCurrentUser(ctx *gin.Context) {
	// Get the token from the request header (Authorization: Bearer <token>)
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is missing"})
		return
	}

	// Validate and parse the token to get the user info (you may need to implement a method to validate and extract user info)
	user, err := c.authService.GetUserFromToken(ctx, token)//built by DPS...needs debugging
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	// Return the current user information as a response
	ctx.JSON(http.StatusOK, gin.H{"user": user})
}
// UpdateCurrentUser updates the authenticated user's information
func (c *AuthController) UpdateCurrentUser(ctx *gin.Context) {
	// Get the token from the request header (Authorization: Bearer <token>)
	token := ctx.GetHeader("Authorization")
	if token == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is missing"})
		return
	}

	// Validate and parse the token to get the user info
	user, err := c.authService.GetUserFromToken(ctx, token)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	// Bind the request data (e.g., JSON body) to a user struct for updating
	var updatedUserData services.UserUpdateRequest
	if err := ctx.ShouldBindJSON(&updatedUserData); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	// Call the service to update the user
	updatedUser, err := c.authService.UpdateUser(ctx, user.ID, updatedUserData)//built by DPS...needs debugging
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user information"})
		return
	}

	// Return the updated user data
	ctx.JSON(http.StatusOK, gin.H{"user": updatedUser})
}
// UpdateUser handles the user update request
// func (c *AuthController) UpdateUser(ctx *gin.Context) {
//     var user models.User
//     if err := ctx.ShouldBindJSON(&user); err != nil {
//         c.logger.Error("Failed to bind user data", zap.Error(err))
//         ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user data"})
//         return
//     }

//     // Get the user ID from the request or token (if needed)
//     userID := ctx.Param("user_id")
//     if userID == "" {
//         c.logger.Error("User ID is required", zap.String("user_id", userID))
//         ctx.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
//         return
//     }

//     // Prepare the updates (this can be customized as per the request body)
//     updates := map[string]interface{}{
//         "email": user.Email,
//         "name":  user.Name,
//     }

//     // Find the user from the database using the user ID
//     var existingUser models.User
//     err := c.authService.db.First(&existingUser, userID).Error
//     if err != nil {
//         c.logger.Error("User not found", zap.Error(err))
//         ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
//         return
//     }

//     // Update the user
//     err = c.authService.UpdateUser(ctx, &existingUser, updates)
//     if err != nil {
//         c.logger.Error("Failed to update user", zap.Error(err))
//         ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
//         return
//     }

//     ctx.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// }

// // HandleCallback processes the authentication callback
// func (c *AuthController) HandleCallback(ctx *gin.Context) {
//     // Handle the callback logic (from the AuthService)
// }