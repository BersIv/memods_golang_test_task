package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"memods_golang_test_task/util"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type service struct {
	Repository
	timeout time.Duration
	util.TokenHasher
	util.TokenParser
}

func NewService(r Repository, h util.TokenHasher, tg util.TokenParser) Service {
	return &service{
		Repository:  r,
		TokenHasher: h,
		TokenParser: tg,
		timeout:     time.Duration(10) * time.Second,
	}
}

func (s *service) getNewTokens(c context.Context, userReq *GetUserReq) (*NewTokensRes, error) {
	ctx, cancel := context.WithTimeout(c, s.timeout)
	defer cancel()

	user, err := s.Repository.getUserById(ctx, userReq)
	if err != nil {
		return nil, err
	}
	user.Ip = userReq.Ip
	tokens, err := newTokens(user)
	if err != nil {
		return nil, err
	}
	response := NewTokensRes{AccessToken: tokens.AccessToken, RefreshToken: base64.StdEncoding.EncodeToString([]byte(tokens.RefreshToken))}
	tokens.RefreshToken, err = s.TokenHasher.HashToken(tokens.RefreshToken)
	if err != nil {
		return nil, err
	}

	err = s.Repository.updateRefreshToken(ctx, &user.Id, tokens)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (s *service) checkTokens(c context.Context, req *RefreshTokenReq) (*string, error) {
	decodedRefreshToken, err := base64.StdEncoding.DecodeString(req.RefreshToken.Value)
	if err != nil {
		return nil, err
	}
	accessClaims, err := s.TokenParser.CheckAccessToken(req.AccessToken.Value)
	if err != nil {
		return nil, err
	}
	refreshIp, err := parseRefreshToken(string(decodedRefreshToken))
	if err != nil {
		return nil, err
	}

	if accessClaims.ClientIp != req.Ip || refreshIp != req.Ip {
		//TODO Mail
		log.Println("Ip changed!")
	}

	ctx, cancel := context.WithTimeout(c, s.timeout)
	defer cancel()
	refreshToken, used, err := s.Repository.getRefreshToken(ctx, &accessClaims.ID)
	if err != nil {
		return nil, err
	}
	if *used {
		return nil, errors.New("refresh token already used")
	}

	err = s.TokenHasher.CompareTokens(*refreshToken, string(decodedRefreshToken))
	if err != nil {
		return nil, err
	}

	err = s.Repository.setUsedRefreshToken(ctx, &accessClaims.ID)
	if err != nil {
		return nil, err
	}
	return &accessClaims.UserId, nil
}

func newTokens(user *User) (*NewTokens, error) {
	if user.Id == "" || user.Username == "" || user.Ip == "" {
		return nil, errors.New("user shouldn't have empty fields")
	}
	accessTokenId := uuid.New().String()
	aT := jwt.NewWithClaims(jwt.SigningMethodHS512, util.AccessTokenClaims{
		UserId:   user.Id,
		Nickname: user.Username,
		ClientIp: user.Ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:        accessTokenId,
		},
	})
	secretKey := os.Getenv("SECRET_KEY")
	accessToken, err := aT.SignedString([]byte(secretKey))
	if err != nil {
		return nil, err
	}

	bytes := make([]byte, 16)
	_, err = rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	expiredAt := time.Now().Add(24 * time.Hour)
	refreshToken := fmt.Sprintf("%s|%s|%s", string(bytes), user.Ip, expiredAt.Format("15:04 2006-01-02"))

	return &NewTokens{AccessTokenId: accessTokenId, AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func parseRefreshToken(refreshToken string) (string, error) {
	token := strings.Split(refreshToken, "|")
	if len(token) != 3 {
		return "", errors.New("invalid refresh token")
	}

	expiredAt, err := time.Parse("15:04 2006-01-02", token[2])
	if err != nil {
		return "", err
	}

	if time.Now().After(expiredAt) {
		return "", errors.New("refresh token expired")
	}

	return token[1], nil
}
