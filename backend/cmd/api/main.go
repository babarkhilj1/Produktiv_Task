package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/swaggo/gin-swagger"
    // "github.com/swaggo/gin-swagger/swaggerFiles"
    "go.uber.org/zap"
     "net/http"
    "backend/config"
    "backend/internal/controllers"
    "backend/internal/middleware"
    "backend/internal/services"
    "backend/pkg/database"
    "backend/pkg/cache"
)

func main() {
    // Initialize logger
    logger, err := zap.NewProduction()
    if err != nil {
        log.Fatal("Failed to initialize logger:", err)
    }
    defer logger.Sync()

    // Load configuration
    cfg, err := config.LoadConfig()
    if err != nil {
        logger.Fatal("Failed to load configuration", zap.Error(err))
    }

    // Set Gin mode
    if cfg.App.Env == "development" {
        gin.SetMode(gin.ReleaseMode)
    }

    // Initialize database
    db, err := database.InitPostgres(&cfg.Database.Postgres)
    if err != nil {
        logger.Fatal("Failed to initialize database", zap.Error(err))
    }

    // Initialize Redis
    redisClient, err := cache.InitRedis(&cfg.Redis)
    if err != nil {
        logger.Fatal("Failed to initialize Redis", zap.Error(err))
    }
    defer redisClient.Close()

    // Initialize services
    microsoftService := services.NewMicrosoftEntraService(cfg)
    keycloakService := services.NewKeycloakService(cfg, microsoftService)
    authService := services.NewAuthService(db, redisClient, keycloakService, cfg)
    sessionService := services.NewSessionService(db, redisClient, cfg)

    // Initialize controllers
    authController := controllers.NewAuthController(authService, sessionService)
    sessionController := controllers.NewSessionController(sessionService)

    // Initialize Gin router
    router := gin.New()

    // Apply global middleware
    router.Use(gin.Recovery())
    router.Use(middleware.CORSMiddleware(cfg))
    router.Use(middleware.RequestLogger(logger))//built by DPS...may require debugging

    // Initialize routes
    initializeRoutes(router, cfg, authController, sessionController, authService)

    // Create server
    srv := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.App.Port),
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    // Start server in a goroutine
    go func() {
        logger.Info("Starting server", zap.String("port", srv.Addr))
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("Failed to start server", zap.Error(err))
        }
    }()

    // Start session cleanup routine
    go runSessionCleanup(sessionService, cfg.Session.CleanupInterval, logger)

    // Wait for interrupt signal to gracefully shut down the server
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    logger.Info("Shutting down server...")

    // Create shutdown context with 10 second timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Shutdown server
    if err := srv.Shutdown(ctx); err != nil {
        logger.Fatal("Server forced to shutdown", zap.Error(err))
    }

    logger.Info("Server exited successfully")
}

func initializeRoutes(
    router *gin.Engine,
    cfg *config.Config,
    authController *controllers.AuthController,
    sessionController *controllers.SessionController,
    authService *services.AuthService,
) {
    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "ok"})
    })

    // API routes
    api := router.Group("/api")
    {
        // Auth routes
        auth := api.Group("/auth")
        {
            // Microsoft Entra ID routes
            auth.GET("/microsoft/login", authController.InitiateMicrosoftLogin)//built and debugged by DPS
            auth.GET("/microsoft/callback", authController.HandleMicrosoftCallback)//built and debugged by DPS
            
            // Keycloak routes
            auth.GET("/login", authController.InitiateLogin)// built by DPS need debugging of functions in auth_service
            auth.GET("/callback", authController.HandleCallback)//built by DPS may need debugging  
            
            // Token and session management
            auth.POST("/validate", authController.ValidateToken)// built by DPS need to build ValidateIDToken in auth_services.go
            auth.POST("/refresh", authController.RefreshToken)//built by DPS need to build RefreshAccessToken in microsoft_services.go 
            auth.POST("/logout", middleware.AuthMiddleware(authService), authController.Logout)//built by DPS need to build InvalidateSession in session_service.go
        }

        // Protected routes
        protected := api.Group("")
        protected.Use(middleware.AuthMiddleware(authService))
        {
            // Session management
            sessions := protected.Group("/sessions")
            {
                sessions.GET("/current", sessionController.GetCurrentSession)//built by DPS 
                sessions.DELETE("/current", sessionController.DeleteCurrentSession)//built by DPS
                sessions.GET("/all", sessionController.GetAllSessions)//built by DPS...need to build sessionService.GetAllSessions
                sessions.DELETE("/all", sessionController.DeleteAllSessions)//built by DPS...need to build sessionService.DeleteAllSessions
            }

            // User management
            users := protected.Group("/users")
            {
                users.GET("/me", authController.GetCurrentUser)//built by DPS...need to build GetCurrentUser in auth_services.go
                users.PUT("/me", authController.UpdateCurrentUser)//built by DPS...need to build multiple function in auth_services.go
            }
        }
    }

    // Swagger documentation
    if cfg.App.Env == "development" {
        router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
    }
}

func runSessionCleanup(sessionService *services.SessionService, cleanupInterval time.Duration, logger *zap.Logger) {
    ticker := time.NewTicker(cleanupInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := sessionService.CleanExpiredSessions(); err != nil {
                logger.Error("Failed to clean expired sessions", zap.Error(err))
            }
        }
    }
}
