package controllers

import (
	"backend/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SessionController struct {
    sessionService *services.SessionService
}

func NewSessionController(sessionService *services.SessionService) *SessionController {
    return &SessionController{
        sessionService: sessionService,
    }
}

func (c *SessionController) GetSession(ctx *gin.Context) {
    token := ctx.Param("token")
    
    session, err := c.sessionService.GetSession(ctx, token)
    if err != nil {
        ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }

    ctx.JSON(http.StatusOK, session)
}

func (c *SessionController) DeleteSession(ctx *gin.Context) {
    token := ctx.Param("token")
    
    if err := c.sessionService.DeleteSession(ctx, token); err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    ctx.Status(http.StatusNoContent)
}
// GetCurrentSession retrieves the current user's session.DPS
func (c *SessionController) GetCurrentSession(ctx *gin.Context) {
    // Here we assume the session token is stored in the request headers or as a cookie
    token := ctx.GetHeader("Authorization") // or you could use ctx.Cookie("session_token")
    
    if token == "" {
        ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is missing"})
        return
    }

    session, err := c.sessionService.GetSession(ctx, token)
    if err != nil {
        ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
        return
    }

    ctx.JSON(http.StatusOK, session)
}
// DeleteCurrentSession deletes the current user's session.DPS
func (c *SessionController) DeleteCurrentSession(ctx *gin.Context) {
    // Here we assume the session token is passed in the Authorization header or as a cookie
    token := ctx.GetHeader("Authorization") // or ctx.Cookie("session_token")
    
    if token == "" {
        ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is missing"})
        return
    }

    if err := c.sessionService.DeleteSession(ctx, token); err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    ctx.Status(http.StatusNoContent)
}
// GetAllSessions retrieves all sessions
func (c *SessionController) GetAllSessions(ctx *gin.Context) {
    sessions, err := c.sessionService.GetAllSessions(ctx)//built by DPS
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    ctx.JSON(http.StatusOK, sessions)
}
// DeleteAllSessions deletes all sessions
func (c *SessionController) DeleteAllSessions(ctx *gin.Context) {
    err := c.sessionService.DeleteAllSessions(ctx)//built by DPS
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    ctx.Status(http.StatusNoContent) // No content, successful deletion
}