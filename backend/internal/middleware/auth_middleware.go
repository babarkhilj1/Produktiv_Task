package middleware

import (
    "log"
    "net/http"
    "strings"
    "backend/config"
    "github.com/gin-gonic/gin"
    "backend/internal/services"
)

func AuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
    return func(ctx *gin.Context) {
        authHeader := ctx.GetHeader("Authorization")
        if authHeader == "" {
            ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
            return
        }

        // Extract token
        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == authHeader {
            ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
            return
        }

        // Validate token and get user
        user, err := authService.ValidateToken(ctx, token)//need to have a look 
        if err != nil {
            ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }

        // Set user in context
        ctx.Set("user", user)
        ctx.Set("userID", user.ID)
        
        ctx.Next()
    }
}

func CORSMiddleware(config *config.Config) gin.HandlerFunc {
    return func(ctx *gin.Context) {
        origin := ctx.Request.Header.Get("Origin")
        for _, allowedOrigin := range config.App.AllowedOrigins {
            if origin == allowedOrigin {
                ctx.Writer.Header().Set("Access-Control-Allow-Origin", origin)
                break
            }
        }
        
        ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

        if ctx.Request.Method == "OPTIONS" {
            ctx.AbortWithStatus(204)
            return
        }

        ctx.Next()
    }
}
// RequestLogger logs incoming requests
func RequestLogger() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        // Log the incoming request details (e.g., method, URL, and client IP)
        log.Printf("Request: %s %s, IP: %s", ctx.Request.Method, ctx.Request.URL.Path, ctx.ClientIP())

        // Continue processing the request
        ctx.Next()

        // Optionally, you can log response status as well after the request is processed
        log.Printf("Response status: %d", ctx.Writer.Status())
    }
}