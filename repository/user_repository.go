package repository

import (
	"database/sql"
	"errors"

	"github.com/g4l1l10/authentication/db"
	"github.com/g4l1l10/authentication/models"
	"github.com/google/uuid"
)

// CreateUser inserts a new user into the database.
func CreateUser(user *models.User) error {
	query := `INSERT INTO users (id, email, password, refresh_token, created_at, updated_at, deleted_at, last_password_change) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := db.DB.Exec(query, user.ID, user.Email, user.Password, user.RefreshToken, user.CreatedAt, user.UpdatedAt, user.DeletedAt, user.LastPasswordChange)
	return err
}

// GetUserByID retrieves a user by UUID, excluding soft-deleted users.
func GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, refresh_token, created_at, updated_at, deleted_at, last_password_change FROM users 
	          WHERE id = $1 AND deleted_at IS NULL`

	row := db.DB.QueryRow(query, userID)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.RefreshToken, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt, &user.LastPasswordChange)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No active user found
		}
		return nil, err
	}
	return &user, nil
}

// UpdateUser modifies a user's email and password, updating the updated_at timestamp.
func UpdateUser(user *models.User) error {
	query := `UPDATE users SET email = $1, password = $2, updated_at = current_timestamp WHERE id = $3`
	_, err := db.DB.Exec(query, user.Email, user.Password, user.ID)
	return err
}

// UpdateRefreshToken updates a user's refresh token and updates the timestamp.
func UpdateRefreshToken(userID uuid.UUID, refreshToken string) error {
	query := `UPDATE users SET refresh_token = $1, updated_at = current_timestamp WHERE id = $2`
	_, err := db.DB.Exec(query, refreshToken, userID)
	return err
}

// SoftDeleteUser marks a user as deleted without removing them from the database.
func SoftDeleteUser(userID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = current_timestamp WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// RestoreUser removes the soft-delete flag, restoring the user.
func RestoreUser(userID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NULL WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// DeleteUser permanently removes a user from the database.
func DeleteUser(userID uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// GetRefreshToken retrieves the refresh token for a user by ID.
func GetRefreshToken(userID uuid.UUID) (string, error) {
	var refreshToken string
	query := `SELECT refresh_token FROM users WHERE id = $1`

	err := db.DB.QueryRow(query, userID).Scan(&refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // No refresh token found
		}
		return "", err
	}

	return refreshToken, nil
}

