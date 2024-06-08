package auth

import (
	"context"
)

type User struct {
	Id       string `json:"Id"`
	Username string `json:"Username"`
	Password string `json:"Password"`
	Ip       string `json:"Ip"`
}

type NewTokens struct {
	AccessTokenId string `json:"AccessTokenId"`
	AccessToken   string `json:"AccessToken"`
	RefreshToken  string `json:"RefreshToken"`
}

type NewTokensRes struct {
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
}

type Repository interface {
	getUserById(ctx context.Context, user *User) (*User, error)
	newRefreshToken(ctx context.Context, userId string, tokens *NewTokens) error
}

type Service interface {
	getTokens(c context.Context, user *User) (tokens *NewTokensRes, err error)
}
