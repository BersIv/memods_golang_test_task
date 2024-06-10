package mocks

type MockHasher struct {
	Token string
	Err   error
}

func (m *MockHasher) HashToken(token string) (string, error) {
	return m.Token, m.Err
}

func (m *MockHasher) CompareTokens(databseToken string, cookieToken string) error {
	return m.Err
}
