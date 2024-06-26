package auth

import (
	"context"
	"net/http"
)

type User struct {
	Id       string `json:"Id"`
	Username string `json:"Username"`
	Password string `json:"Password"`
	Ip       string `json:"Ip"`
}

type GetUserReq struct {
	Id string `json:"Id"`
	Ip string `json:"Ip"`
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
	AccessToken  http.Cookie
	RefreshToken http.Cookie
	Ip           string
}

type Repository interface {
	getUserById(ctx context.Context, userReq *GetUserReq) (*User, error)
	updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error
	getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error)
	setUsedRefreshToken(ctx context.Context, accessTokenId *string) error
}

type Service interface {
	getNewTokens(c context.Context, userReq *GetUserReq) (tokens *NewTokensRes, err error)
	checkTokens(c context.Context, req *RefreshTokenReq) (*string, error)
}
