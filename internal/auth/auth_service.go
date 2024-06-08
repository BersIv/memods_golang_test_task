package auth

import (
	"context"
	"encoding/base64"
	"memods_golang_test_task/util"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type service struct {
	Repository
	timeout time.Duration
}

type MyCustomClaims struct {
	UserId   string `json:"Id"`
	Nickname string `json:"Nickname"`
	ClientIp string `json:"ClientIp"`
	jwt.RegisteredClaims
}

func NewService(r Repository) Service {
	return &service{
		Repository: r,
		timeout:    time.Duration(2) * time.Second,
	}
}

func (s *service) getNewTokens(c context.Context, userId *string) (*NewTokensRes, error) {
	ctx, cancel := context.WithTimeout(c, s.timeout)
	defer cancel()

	user, err := s.Repository.getUserById(ctx, userId)
	if err != nil {
		return &NewTokensRes{}, err
	}

	tokens, err := newTokens(user)
	if err != nil {
		return &NewTokensRes{}, err
	}
	response := NewTokensRes{AccessToken: tokens.AccessToken, RefreshToken: base64.StdEncoding.EncodeToString([]byte(tokens.RefreshToken))}
	tokens.RefreshToken, err = util.HashToken(tokens.RefreshToken)
	if err != nil {
		return &NewTokensRes{}, err
	}

	err = s.Repository.updateRefreshToken(ctx, &user.Id, tokens)
	if err != nil {
		return &NewTokensRes{}, err
	}

	return &response, nil
}

func (s *service) getRefreshToken(c context.Context, accessTokenId *string) (*string, error) {
	ctx, cancel := context.WithTimeout(c, s.timeout)
	defer cancel()

	token, err := s.Repository.getRefreshToken(ctx, accessTokenId)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func newTokens(user *User) (*NewTokens, error) {
	accessTokenId := uuid.New().String()
	aT := jwt.NewWithClaims(jwt.SigningMethodHS512, MyCustomClaims{
		UserId:   user.Id,
		Nickname: user.Username,
		ClientIp: user.Ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        accessTokenId,
		},
	})
	secretKey := os.Getenv("SECRET_KEY")
	accessToken, err := aT.SignedString([]byte(secretKey))
	if err != nil {
		return &NewTokens{}, err
	}
	refreshToken := uuid.New().String()

	return &NewTokens{AccessTokenId: accessTokenId, AccessToken: accessToken, RefreshToken: refreshToken}, nil
}
