package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/g4l1l10/authentication/db"
	"github.com/g4l1l10/authentication/middlewares"
	"github.com/g4l1l10/authentication/models"
	"github.com/g4l1l10/authentication/routes"
	"github.com/g4l1l10/authentication/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Setup test router
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.Use(middlewares.CORSMiddleware()) // Enable CORS
	routes.AuthRoutes(router)
	return router
}

// Test User Registration
func TestRegisterUser(t *testing.T) {
	router := setupRouter()

	// Mock request body
	body := map[string]string{
		"email":    "testuser@example.com",
		"password": "securepassword",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// Test User Login
func TestLoginUser(t *testing.T) {
	router := setupRouter()

	// First, register the user (if not already in DB)
	password, _ := utils.HashPassword("securepassword")
	mockUser := models.User{
		ID:        uuid.New(),
		Email:     "testuser@example.com",
		Password:  password,
		CreatedAt: time.Now(),
	}
	db.DB.Exec("INSERT INTO users (id, email, password, created_at) VALUES ($1, $2, $3, $4)",
		mockUser.ID, mockUser.Email, mockUser.Password, mockUser.CreatedAt)

	// Login request
	body := map[string]string{
		"email":    "testuser@example.com",
		"password": "securepassword",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Extract JWT Token from response
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotEmpty(t, response["token"], "Token should not be empty")
}

// Test JWT Protected Route (Get User)
func TestProtectedGetUserRoute(t *testing.T) {
	router := setupRouter()

	// Mock a user with a valid JWT token
	userID := uuid.New()
	token, _ := utils.GenerateToken(userID)

	req, _ := http.NewRequest("GET", "/users/"+userID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Test Unauthorized Access (Missing Token)
func TestUnauthorizedAccess(t *testing.T) {
	router := setupRouter()

	req, _ := http.NewRequest("GET", "/users/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
