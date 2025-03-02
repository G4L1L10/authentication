package services

import (
	"errors"
	"strings"
	"time"

	"github.com/g4l1l10/authentication/models"
	"github.com/g4l1l10/authentication/repository"
	"github.com/g4l1l10/authentication/utils"

	"github.com/google/uuid"
)

// RegisterUser registers a new user.
func RegisterUser(email, password string) (*models.User, error) {
	// Normalize email (convert to lowercase)
	email = strings.ToLower(email)

	// Check if the user already exists
	existingUser, _ := repository.GetUserByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	// Validate password strength
	if err := utils.ValidatePassword(password); err != nil {
		return nil, err
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create a new user model
	user := &models.User{
		ID:                 uuid.New(),
		Email:              email,
		Password:           hashedPassword,
		CreatedAt:          time.Now(),
		LastPasswordChange: time.Now(), // Track password change
	}

	// Save the user
	err = repository.CreateUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// LoginUser authenticates a user and returns an access token and the same refresh token unless refreshed.
func LoginUser(email, password string) (string, string, error) {
	// Normalize email
	email = strings.ToLower(email)

	// Find user by email
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return "", "", errors.New("invalid credentials")
	}

	// Compare hashed passwords
	if !utils.ComparePassword(user.Password, password) {
		return "", "", errors.New("invalid credentials")
	}

	// Generate a new **access token** (expires in 15 minutes)
	accessToken, err := utils.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", err
	}

	// Fetch the refresh token from DB
	existingRefreshToken, err := repository.GetRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	var refreshToken string
	if existingRefreshToken == "" {
		// If no refresh token exists, generate a new one
		refreshToken, err = utils.GenerateRefreshToken(user.ID)
		if err != nil {
			return "", "", err
		}

		// Store the refresh token in the database **ONLY IF IT'S NEW**
		err = repository.UpdateRefreshToken(user.ID, refreshToken)
		if err != nil {
			return "", "", err
		}
	} else {
		// If a refresh token already exists, use it
		refreshToken = existingRefreshToken
	}

	return accessToken, refreshToken, nil
}

// LogoutUser removes the refresh token from the database, effectively logging the user out.
func LogoutUser(userID uuid.UUID) error {
	return repository.UpdateRefreshToken(userID, "")
}
