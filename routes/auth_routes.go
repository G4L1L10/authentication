package routes

import (
	"github.com/g4l1l10/authentication/controllers"
	"github.com/g4l1l10/authentication/middlewares"
	"github.com/gin-gonic/gin"
)

// AuthRoutes sets up authentication-related routes
func AuthRoutes(router *gin.Engine) {
	auth := router.Group("/auth")
	{
		auth.POST("/register", controllers.Register)    // Admin Registration
		auth.POST("/login", controllers.Login)          // Admin Login
		auth.POST("/logout", controllers.Logout)        // Logout Route
		auth.POST("/refresh", controllers.RefreshToken) // Refresh Token Route

		// ✅ Added token validation endpoint for RSVP backend
		auth.GET("/validate", controllers.AuthValidate) // Token Validation
	}

	// Protected routes require JWT authentication
	protected := router.Group("/users").Use(middlewares.AuthMiddleware())
	{
		protected.GET("/:id", controllers.GetUser)       // Get user by ID
		protected.PUT("/:id", controllers.UpdateUser)    // Update user details
		protected.DELETE("/:id", controllers.DeleteUser) // Delete user account
	}
}
