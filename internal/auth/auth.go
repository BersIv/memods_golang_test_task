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

type RefreshTokenReq struct {
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
}

type Repository interface {
	getUserById(ctx context.Context, userId *string) (*User, error)
	updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error
	getRefreshToken(ctx context.Context, accessTokenId *string) (*string, error)
}

type Service interface {
	getNewTokens(c context.Context, userId *string) (tokens *NewTokensRes, err error)
	getRefreshToken(ctx context.Context, accessTokenId *string) (*string, error)
}
