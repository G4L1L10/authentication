package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents the admin user in the authentication system
type User struct {
	ID        uuid.UUID  `json:"id"`                   // Unique User ID (UUID)
	Email     string     `json:"email"`                // Admin Email (Unique)
	Password  string     `json:"password"`             // Hashed Password
	CreatedAt time.Time  `json:"created_at"`           // Timestamp when the user was created
	UpdatedAt time.Time  `json:"updated_at"`           // Timestamp when the user was last updated
	DeletedAt *time.Time `json:"deleted_at,omitempty"` // Nullable field for soft deletes
}

// NewUser creates a new user instance with a generated UUID and timestamps
func NewUser(email, hashedPassword string) *User {
	currentTime := time.Now()
	return &User{
		ID:        uuid.New(), // Generate new UUID
		Email:     email,
		Password:  hashedPassword,
		CreatedAt: currentTime, // Set creation timestamp
		UpdatedAt: currentTime, // Initially set updatedAt to the same value as createdAt
		DeletedAt: nil,         // Ensure the user is active by default
	}
}

// UpdateUser updates user details and refreshes the updatedAt timestamp
func (u *User) UpdateUser(email, hashedPassword string) {
	u.Email = email
	u.Password = hashedPassword
	u.UpdatedAt = time.Now() // Update timestamp
}

// SoftDelete marks a user as deleted by setting DeletedAt timestamp
func (u *User) SoftDelete() {
	currentTime := time.Now()
	u.DeletedAt = &currentTime
}

// Restore restores a soft-deleted user
func (u *User) Restore() {
	u.DeletedAt = nil
}
