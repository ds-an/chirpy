package auth_test

import (
	"testing"
	"time"

	"github.com/ds-an/chirpy/internal/auth"
	"github.com/google/uuid"
)

func TestJWT(t *testing.T) {
    secret := "my-super-secret-key"
    userID := uuid.New()
    expiresIn := time.Hour

    token, err := auth.MakeJWT(userID, secret, expiresIn)
    if err != nil {
        t.Fatalf("failed to make jwt: %v", err)
    }

    validatedID, err := auth.ValidateJWT(token, secret)
    if err != nil {
        t.Fatalf("failed to validate jwt: %v", err)
    }

    if validatedID != userID {
        t.Errorf("expected %v, got %v", userID, validatedID)
    }
}

func TestExpiredJWT(t *testing.T) {
    secret := "my-super-secret-key"
    userID := uuid.New()
    expiresIn := -time.Hour

    token, err := auth.MakeJWT(userID, secret, expiresIn)
    if err != nil {
        t.Fatalf("failed to make jwt: %v", err)
    }

    _, err = auth.ValidateJWT(token, secret)
    if err == nil {
        t.Fatalf("incorrectly validated jwt")
    }
}

func TestWrongSecret(t *testing.T) {
    secret := "my-super-secret-key"
    userID := uuid.New()
    expiresIn := time.Hour

    token, err := auth.MakeJWT(userID, secret, expiresIn)
    if err != nil {
        t.Fatalf("failed to make jwt: %v", err)
    }

    incorrectSecret := "my-super-incorrect-key"
    _, err = auth.ValidateJWT(token, incorrectSecret)
    if err == nil {
        t.Fatalf("failed to recognize that the secret is incorrect")
    }
}
