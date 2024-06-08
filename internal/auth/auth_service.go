package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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

type CustomError struct {
	code    int
	message string
}

func (e CustomError) Error() string {
	return fmt.Sprintf("error %d: %s", e.code, e.message)
}

func NewService(r Repository) Service {
	return &service{
		Repository: r,
		timeout:    time.Duration(15) * time.Second,
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

func (s *service) checkTokens(c context.Context, req *RefreshTokenReq) (*string, error) {
	decodedRefreshToken, err := base64.StdEncoding.DecodeString(req.RefreshToken.Value)
	if err != nil {
		return nil, err
	}
	secret := os.Getenv("SECRET_KEY")
	token, err := jwt.ParseWithClaims(req.AccessToken.Value, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*MyCustomClaims)
	if !ok || !token.Valid {
		return nil, err
	}
	if claims.ClientIp != req.Ip {
		//TODO Mail
		log.Println("Ip changed!")
	}

	ctx, cancel := context.WithTimeout(c, s.timeout)
	defer cancel()
	refreshToken, used, err := s.Repository.getRefreshToken(ctx, &claims.ID)
	if err != nil {
		return nil, err
	}
	if *used {
		return nil, errors.New("refresh token already used")
	}

	err = util.CompareTokens(*refreshToken, string(decodedRefreshToken))
	if err != nil {
		return nil, err
	}

	err = s.setUsedRefreshToken(ctx, &claims.ID)
	if err != nil {
		return nil, err
	}
	return &claims.UserId, nil
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
