package util

import (
	"golang.org/x/crypto/bcrypt"
)

func HashToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedToken), nil
}

func CompareTokens(databseToken string, cookieToken string) error {
	return bcrypt.CompareHashAndPassword([]byte(databseToken), []byte(cookieToken))
}
