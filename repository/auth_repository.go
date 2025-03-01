package repository

import (
	"database/sql"
	"errors"

	"github.com/g4l1l10/authentication/db"
	"github.com/g4l1l10/authentication/models"
	"github.com/g4l1l10/authentication/utils"
	"github.com/google/uuid"
)

// GetUserByEmail retrieves a user by email for authentication, excluding soft-deleted users.
func GetUserByEmail(email string) (*models.User, error) {
	var user models.User

	query := `SELECT id, email, password, created_at, updated_at, deleted_at FROM users WHERE email = $1 AND deleted_at IS NULL`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	row := stmt.QueryRow(email)
	err = row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No user found
		}
		return nil, err
	}

	return &user, nil
}

// UpdatePassword securely updates the user's password.
func UpdatePassword(userID uuid.UUID, hashedPassword string) error {
	query := `UPDATE users SET password = $1, updated_at = current_timestamp WHERE id = $2`
	stmt, err := db.DB.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(hashedPassword, userID)
	return err
}

// VerifyCredentials checks if the provided email and password are correct.
func VerifyCredentials(email, inputPassword string) (*models.User, error) {
	user, err := GetUserByEmail(email)
	if err != nil || user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Compare hashed passwords
	if !utils.ComparePassword(user.Password, inputPassword) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}
