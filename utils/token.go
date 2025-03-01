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

// GenerateTokens creates an **access token** (15 min) and a **refresh token** (7 days).
func GenerateTokens(userID uuid.UUID) (string, string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	// Short-lived Access Token (15 min)
	accessTokenExpiration := time.Now().Add(15 * time.Minute)
	accessClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	// Long-lived Refresh Token (7 days)
	refreshTokenExpiration := time.Now().Add(7 * 24 * time.Hour)
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
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

