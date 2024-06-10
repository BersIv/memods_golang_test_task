package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"memods_golang_test_task/mocks"
	"memods_golang_test_task/util"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MockRepo struct{}

func (m *MockRepo) getUserById(ctx context.Context, userReq *GetUserReq) (*User, error) {
	return &User{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Username: "test", Password: "Test"}, nil
}

func (m *MockRepo) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {
	return nil
}

func (m *MockRepo) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error) {
	used := false
	token := "$2a$10$zi1Pxsxtz.jrSxqKP2edee.Gng8SboAlnkU88vSSvMTzQfFHyoYSq"
	return &token, &used, nil
}

func (m *MockRepo) setUsedRefreshToken(ctx context.Context, accessTokenId *string) error {
	return nil
}

type MockRepoError struct{}

func (m *MockRepoError) getUserById(ctx context.Context, userReq *GetUserReq) (*User, error) {
	return nil, errors.New("fake error")
}

func (m *MockRepoError) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {
	return nil
}

func (m *MockRepoError) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error) {
	return nil, nil, errors.New("fake error")
}

func (m *MockRepoError) setUsedRefreshToken(ctx context.Context, accessTokenId *string) error {
	return errors.New("fake error")
}

type MockRepoSecondError struct{}

func (m *MockRepoSecondError) getUserById(ctx context.Context, userReq *GetUserReq) (*User, error) {
	return &User{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Username: "test", Password: "Test"}, nil
}

func (m *MockRepoSecondError) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {
	return errors.New("fake error")
}
func (m *MockRepoSecondError) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error) {
	boolean := true
	return nil, &boolean, nil
}

func (m *MockRepoSecondError) setUsedRefreshToken(ctx context.Context, accessTokenId *string) error {
	return nil
}

type MockRepoNewTokenError struct{}

func (m *MockRepoNewTokenError) getUserById(ctx context.Context, userReq *GetUserReq) (*User, error) {
	return &User{}, nil
}

func (m *MockRepoNewTokenError) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {
	return nil
}
func (m *MockRepoNewTokenError) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error) {
	return nil, nil, nil
}

func (m *MockRepoNewTokenError) setUsedRefreshToken(ctx context.Context, accessTokenId *string) error {
	return nil
}

type MockSetUsedError struct{}

func (m *MockSetUsedError) getUserById(ctx context.Context, userReq *GetUserReq) (*User, error) {
	return &User{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Username: "test", Password: "Test"}, nil
}

func (m *MockSetUsedError) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {
	return nil
}
func (m *MockSetUsedError) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, *bool, error) {
	used := false
	token := "$2a$10$zi1Pxsxtz.jrSxqKP2edee.Gng8SboAlnkU88vSSvMTzQfFHyoYSq"
	return &token, &used, nil
}

func (m *MockSetUsedError) setUsedRefreshToken(ctx context.Context, accessTokenId *string) error {
	return errors.New("fake error")
}

func TestGetNewTokens(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)

	userReq := GetUserReq{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Ip: "192.0.2.1"}
	ctx := context.Background()
	tokens, err := service.getNewTokens(ctx, &userReq)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if tokens == nil {
		t.Errorf("tokens empty")
	}

}

func TestGetNewTokens_GetRepoError(t *testing.T) {
	mockRepo := &MockRepoError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	userReq := GetUserReq{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Ip: "192.0.2.1"}
	ctx := context.Background()
	tokens, err := service.getNewTokens(ctx, &userReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}

	if tokens != nil {
		t.Errorf("tokens must be empty")
	}
}

func TestGetNewTokens_NewTokensError(t *testing.T) {
	mockRepo := &MockRepoNewTokenError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	userReq := GetUserReq{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Ip: "192.0.2.1"}
	ctx := context.Background()
	tokens, err := service.getNewTokens(ctx, &userReq)
	if err.Error() != "user shouldn't have empty fields" {
		t.Errorf("unexpected error: %s", err)
	}
	if tokens != nil {
		t.Errorf("tokens must be empty")
	}

}

func TestGetNewTokens_UpdateRepoError(t *testing.T) {
	mockRepo := &MockRepoSecondError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	userReq := GetUserReq{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Ip: "192.0.2.1"}
	ctx := context.Background()
	tokens, err := service.getNewTokens(ctx, &userReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if tokens != nil {
		t.Errorf("tokens should be empty")
	}
}

func TestGetNewTokens_HashTokenError(t *testing.T) {
	mockRepo := &MockRepoSecondError{}
	hasher := &mocks.MockHasher{
		Token: "",
		Err:   errors.New("fake error"),
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	userReq := GetUserReq{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410", Ip: "192.0.2.1"}
	ctx := context.Background()
	tokens, err := service.getNewTokens(ctx, &userReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if tokens != nil {
		t.Errorf("tokens should be empty")
	}
}

func TestCheckTokens(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_DecodeError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: "asadsasasssss",
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)

	if !strings.Contains(err.Error(), "illegal base64 data at input byte") {
		t.Errorf("unexpected error format: %s", err)
	}
}

func TestCheckTokens_ParseRefreshTokenError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	refrValue := base64.StdEncoding.EncodeToString([]byte("dsdqasdsada"))
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "invalid refresh token" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_ParseRefreshTokenTimeError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	refrValue := base64.StdEncoding.EncodeToString([]byte("kdjsjdoawqe-0qi-|192.123.1|15esad"))
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if !strings.Contains(err.Error(), "parsing time") {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_ParseRefreshTokenExpiredError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	service := NewService(mockRepo, hasher, tg)
	refrValue := base64.StdEncoding.EncodeToString([]byte("kdjsjdoawqe-0qi-|192.123.1|15:04 2020-01-02"))
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "refresh token expired" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_CheckAccessTokenError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: errors.New("fake error"),
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2100-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_GetRefreshError(t *testing.T) {
	mockRepo := &MockRepoError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2100-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_TokenUsedError(t *testing.T) {
	mockRepo := &MockRepoSecondError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2100-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "refresh token already used" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_SetUsedError(t *testing.T) {
	mockRepo := &MockSetUsedError{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   nil,
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2100-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestCheckTokens_CompareTokensError(t *testing.T) {
	mockRepo := &MockRepo{}
	hasher := &mocks.MockHasher{
		Token: "$2a$10$wwgrIT3UznenX0B1kRfaFunPti/XW4U/IWaIKt7CWZ1QaNiFuaVni",
		Err:   errors.New("fake error"),
	}
	tg := &mocks.MockTokenParser{
		Claims: util.AccessTokenClaims{
			UserId:   "123",
			Nickname: "user",
			ClientIp: "192.168.1.1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				ID:        "dsdqasdsada",
			},
		},
		Err: nil,
	}
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2100-01-02"))
	service := NewService(mockRepo, hasher, tg)
	refreshReq := &RefreshTokenReq{
		AccessToken: http.Cookie{
			Name:  "Access-Token",
			Value: "access_token_value",
		},
		RefreshToken: http.Cookie{
			Name:  "Refresh-Token",
			Value: string(refrValue),
		},
		Ip: "192.168.1.1",
	}

	ctx := context.Background()
	_, err := service.checkTokens(ctx, refreshReq)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
}
