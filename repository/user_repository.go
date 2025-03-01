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
	query := `INSERT INTO users (id, email, password, created_at, updated_at, deleted_at) 
	          VALUES ($1, $2, $3, $4, $5, $6)`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.ID, user.Email, user.Password, user.CreatedAt, user.UpdatedAt, user.DeletedAt)
	return err
}

// GetUserByID retrieves a user by UUID, excluding soft-deleted users.
func GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	query := `SELECT id, email, password, created_at, updated_at, deleted_at FROM users WHERE id = $1 AND deleted_at IS NULL`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(userID)
	err = row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
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
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Email, user.Password, user.ID)
	return err
}

// SoftDeleteUser marks a user as deleted without removing them from the database.
func SoftDeleteUser(userID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = current_timestamp WHERE id = $1`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID)
	return err
}

// RestoreUser removes the soft-delete flag, restoring the user.
func RestoreUser(userID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NULL WHERE id = $1`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID)
	return err
}

// DeleteUser permanently removes a user from the database.
func DeleteUser(userID uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID)
	return err
}
