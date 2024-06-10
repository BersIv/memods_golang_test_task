package util

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type TokenHasher interface {
	HashToken(token string) (string, error)
	CompareTokens(databseToken string, cookieToken string) error
}

type Hasher struct{}

func (Hasher) HashToken(token string) (string, error) {
	if token == "" {
		return "", errors.New("can't hash empty token")
	}
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedToken), nil
}

func (Hasher) CompareTokens(databseToken string, cookieToken string) error {
	return bcrypt.CompareHashAndPassword([]byte(databseToken), []byte(cookieToken))
}
