package util

import (
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	UserId   string `json:"Id"`
	Nickname string `json:"Nickname"`
	ClientIp string `json:"ClientIp"`
	jwt.RegisteredClaims
}

type JWTTokenGetter struct{}

type TokenParser interface {
	CheckAccessToken(accessToken string) (*AccessTokenClaims, error)
}

func (JWTTokenGetter) CheckAccessToken(accessToken string) (*AccessTokenClaims, error) {
	secret := os.Getenv("SECRET_KEY")
	token, err := jwt.ParseWithClaims(accessToken, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	accessClaims, ok := token.Claims.(AccessTokenClaims)
	if !ok || (!token.Valid && !errors.Is(err, jwt.ErrTokenExpired)) {
		return nil, err
	}

	return &accessClaims, nil
}
