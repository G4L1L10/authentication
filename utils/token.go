package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims structure for JWT
type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateToken creates a JWT token for the given user ID.
func GenerateToken(userID uuid.UUID) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	// Short-lived token (15 minutes)
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Expiration time
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // Issued at time
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // Uses HS256
	return token.SignedString(secretKey)
}

// ValidateToken verifies the JWT token and extracts user ID.
func ValidateToken(tokenString string) (*Claims, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Corrected expiration check (without .Time)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

