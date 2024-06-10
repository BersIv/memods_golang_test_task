package mocks

import (
	"memods_golang_test_task/util"
)

type MockTokenParser struct {
	Claims util.AccessTokenClaims
	Err    error
}

func (m *MockTokenParser) CheckAccessToken(accessToken string) (*util.AccessTokenClaims, error) {
	return &m.Claims, m.Err
}
