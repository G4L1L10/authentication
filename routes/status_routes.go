package routes

import (
	"net/http"

	"github.com/g4l1l10/authentication/db"

	"github.com/gin-gonic/gin"
)

// StatusRoutes sets up the health check route
func StatusRoutes(router *gin.Engine) {
	router.GET("/status", func(c *gin.Context) {
		status := "healthy"
		dbStatus := "connected"

		// Check database connectivity
		if err := db.DB.Ping(); err != nil {
			dbStatus = "disconnected"
		}

		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"service":  "Authentication",
			"status":   status,
			"database": dbStatus,
		})
	})
}
