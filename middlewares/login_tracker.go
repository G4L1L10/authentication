package middlewares

import (
	"sync"
	"time"
)

var failedLoginAttempts sync.Map // Tracks failed login attempts per email

// TrackFailedLogin increments failed login attempts
func TrackFailedLogin(email string) {
	attempts, _ := failedLoginAttempts.LoadOrStore(email, 0)

	// Ensure type conversion from interface{} to int
	attemptCount, ok := attempts.(int)
	if !ok {
		attemptCount = 0
	}

	newAttempts := attemptCount + 1
	failedLoginAttempts.Store(email, newAttempts)

	// If 5 failed attempts, lock the account for 1 minute
	if newAttempts >= 5 {
		go func() {
			time.Sleep(1 * time.Minute)       // Lockout duration
			failedLoginAttempts.Delete(email) // Reset attempts after lockout
		}()
	}
}

// IsUserLocked checks if the user is currently locked out
func IsUserLocked(email string) bool {
	attempts, exists := failedLoginAttempts.Load(email)
	if !exists {
		return false
	}

	// Ensure type conversion
	attemptCount, ok := attempts.(int)
	if !ok {
		return false
	}

	return attemptCount >= 5
}

// ResetFailedLogin resets failed login attempts after a successful login
func ResetFailedLogin(email string) {
	failedLoginAttempts.Delete(email)
}
