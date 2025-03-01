package controllers

import (
	"net/http"
	"strings"
	"time"

	"github.com/g4l1l10/authentication/middlewares"
	"github.com/g4l1l10/authentication/repository"
	"github.com/g4l1l10/authentication/services"
	"github.com/g4l1l10/authentication/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Register handles user registration
func Register(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	// Validate input
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize email (convert to lowercase)
	input.Email = strings.ToLower(input.Email)

	// Validate password strength and check against common passwords
	if err := utils.ValidatePassword(input.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Register user
	user, err := services.RegisterUser(input.Email, input.Password)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
		},
	})
}

// Login handles user authentication and JWT token generation
func Login(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	// Validate input
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize email (convert to lowercase)
	input.Email = strings.ToLower(input.Email)

	// Check if user is temporarily locked out
	if middlewares.IsUserLocked(input.Email) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Please try again in 1 minute."})
		return
	}

	// Authenticate user
	accessToken, refreshToken, err := services.LoginUser(input.Email, input.Password)
	if err != nil {
		// Track failed login attempt
		middlewares.TrackFailedLogin(input.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Successful login → Reset failed login counter
	middlewares.ResetFailedLogin(input.Email)

	// Return access and refresh tokens
	c.JSON(http.StatusOK, gin.H{
		"message":       "Login successful",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// RefreshToken generates a new access token using a valid refresh token.
func RefreshToken(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate refresh token
	claims, err := utils.ValidateToken(input.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	// Generate a new access token
	accessToken, _, err := utils.GenerateTokens(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

// GetUser fetches user details (protected route)
func GetUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := repository.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":        user.ID,
		"email":     user.Email,
		"createdAt": user.CreatedAt.Format(time.RFC3339),
	})
}

// UpdateUser updates user details (protected route)
func UpdateUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password,omitempty"`
	}

	// Validate input
	if err = c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize email (convert to lowercase)
	input.Email = strings.ToLower(input.Email)

	// Fetch user from DB
	user, err := repository.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update user details
	user.Email = input.Email
	if input.Password != "" {
		// Validate new password strength
		if err = utils.ValidatePassword(input.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Hash the new password
		hashedPassword, hashErr := utils.HashPassword(input.Password)
		if hashErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		user.Password = hashedPassword
	}

	err = repository.UpdateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully", "user": gin.H{"id": user.ID, "email": user.Email}})
}

// DeleteUser removes a user from the database (protected route)
func DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Fetch user before deleting
	user, err := repository.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Delete user
	err = repository.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
