package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockService struct{}

func (m *MockService) getNewTokens(c context.Context, userReq *GetUserReq) (tokens *NewTokensRes, err error) {
	return &NewTokensRes{AccessToken: "test", RefreshToken: "test"}, nil
}

func (m *MockService) checkTokens(c context.Context, req *RefreshTokenReq) (*string, error) {
	str := "test"
	return &str, nil
}

type MockServiceSqlError struct{}

func (m *MockServiceSqlError) getNewTokens(c context.Context, userReq *GetUserReq) (tokens *NewTokensRes, err error) {
	return &NewTokensRes{}, sql.ErrNoRows
}

func (m *MockServiceSqlError) checkTokens(c context.Context, req *RefreshTokenReq) (*string, error) {
	str := "test"
	return &str, nil
}

type MockServiceError struct{}

func (m *MockServiceError) getNewTokens(c context.Context, userReq *GetUserReq) (tokens *NewTokensRes, err error) {
	return &NewTokensRes{}, errors.New("fake error")
}

func (m *MockServiceError) checkTokens(c context.Context, req *RefreshTokenReq) (*string, error) {
	return nil, errors.New("fake error")
}

func TestGetTokens(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	cookies := rr.Result().Cookies()
	if cookies[0].Value != "test" || cookies[1].Value != "test" {
		t.Errorf("unexpected cookies %v", cookies)
	}
}

func TestGetTokensRealIp(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "194.247.187.44:2312"

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	cookies := rr.Result().Cookies()
	if cookies[0].Value != "test" || cookies[1].Value != "test" {
		t.Errorf("unexpected cookies %v", cookies)
	}
}

func TestGetTokensLocalIp(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "[::1]:54875"

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	cookies := rr.Result().Cookies()
	if cookies[0].Value != "test" || cookies[1].Value != "test" {
		t.Errorf("unexpected cookies %v", cookies)
	}
}

func TestGetTokens_NoPortError(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "[::1]"

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}
}

func TestGetTokens_WrongMethodError(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("POST", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestGetTokens_DecodeError(t *testing.T) {
	requestBody := []byte(`bad json`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestGetTokens_SqlNoRowsError(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")

	svc := &MockServiceSqlError{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestGetTokens_GetNewTokensError(t *testing.T) {
	requestBody := []byte(`{"Id": "dasda-dasdak-dasdlam"}`)
	req, err := http.NewRequest("GET", "/", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")

	svc := &MockServiceError{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.GetTokens(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestRefreshTokens(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&accessCookie)
	req.AddCookie(&refreshCookie)

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestRefreshTokens_WrongMethodError(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&accessCookie)
	req.AddCookie(&refreshCookie)

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestRefreshTokens_BadIpError(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&accessCookie)
	req.AddCookie(&refreshCookie)

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}
}

func TestRefreshTokens_NoAccessCookieError(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.168.1.1")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&refreshCookie)

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestRefreshTokens_NoRefreshCookieError(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}

	req.AddCookie(&accessCookie)

	svc := &MockService{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestRefreshTokens_CheckTokensError(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&accessCookie)
	req.AddCookie(&refreshCookie)

	svc := &MockServiceError{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestRefreshTokens_GetNewTokensError(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Forwarded-For", "192.0.2.1")
	refrValue := base64.StdEncoding.EncodeToString([]byte("	kdjsjdoawqe-0qi-|192.123.1|15:04 2030-01-02"))
	accessCookie := http.Cookie{
		Name:  "Access-Token",
		Value: "access_token_value",
	}
	refreshCookie := http.Cookie{
		Name:  "Refresh-Token",
		Value: string(refrValue),
	}

	req.AddCookie(&accessCookie)
	req.AddCookie(&refreshCookie)

	svc := &MockServiceSqlError{}
	handler := NewHandler(svc)

	rr := httptest.NewRecorder()

	handler.RefreshTokens(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}
