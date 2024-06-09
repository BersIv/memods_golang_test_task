package auth

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetUserById(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mockRow := sqlmock.NewRows([]string{"id", "username", "password"}).
		AddRow("e879426c-ad61-4455-b4b4-07ca20aaf410", "testUsername", "testPassword")

	mock.ExpectQuery("SELECT id, username, password FROM users").WillReturnRows(mockRow)

	repo := NewRepository(db)
	ctx := context.Background()
	userId := "e879426c-ad61-4455-b4b4-07ca20aaf410"
	user, err := repo.getUserById(ctx, &userId)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if user == nil {
		t.Errorf("Expected not nil user")
	}
	expectedUser := User{Id: "e879426c-ad61-4455-b4b4-07ca20aaf410",
		Username: "testUsername",
		Password: "testPassword"}
	if !reflect.DeepEqual(&expectedUser, user) {
		t.Errorf("expected %+v, got %+v", expectedUser, user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetUserById_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT id, username, password FROM users").WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	userId := "e879426c-ad61-4455-b4b4-07ca20aaf410"
	user, err := repo.getUserById(ctx, &userId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	expectedUser := User{}
	if !reflect.DeepEqual(&expectedUser, user) {
		t.Errorf("expected %+v, got %+v", expectedUser, user)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetRefreshToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mockRow := sqlmock.NewRows([]string{"token", "used"}).
		AddRow("$2a$10$aMjU7t63xeK9gn.oBJgjReAUNG2UJ9/bJ.M0wtWzt/egU0aWynX8q", false)

	mock.ExpectQuery("SELECT token, used FROM refresh_tokens").WillReturnRows(mockRow)

	repo := NewRepository(db)
	ctx := context.Background()
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"
	token, used, err := repo.getRefreshToken(ctx, &accessTokenId)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	expectedToken := "$2a$10$aMjU7t63xeK9gn.oBJgjReAUNG2UJ9/bJ.M0wtWzt/egU0aWynX8q"
	expectedUsed := false
	if !reflect.DeepEqual(token, &expectedToken) || !reflect.DeepEqual(used, &expectedUsed) {
		t.Errorf("expected: %v and %v\n got: %v and %v", expectedToken, expectedUsed, token, used)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetRefreshToken_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT token, used FROM refresh_tokens").WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"
	token, used, err := repo.getRefreshToken(ctx, &accessTokenId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if token != nil || used != nil {
		t.Errorf("expected: %v and %v\n got: %v and %v", nil, nil, token, used)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestUpdateRefreshToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	userId := "e879426c-ad61-4455-b4b4-07ca20aaf410"
	tokens := NewTokens{RefreshToken: "$2a$10$aMjU7t63xeK9gn.oBJgjReAUNG2UJ9/bJ.M0wtWzt/egU0aWynX8q",
		AccessTokenId: "4fa2cf1e-203b-4370-9d9a-6088115799be"}

	query := `INSERT INTO refresh_tokens(user_id, token, access_token_id) VALUES($1, $2, $3) 
				ON CONFLICT (user_id) DO UPDATE SET token = $2, access_token_id = $3, used = false`
	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(userId, tokens.RefreshToken, tokens.AccessTokenId).
		WillReturnResult(sqlmock.NewResult(1, 1))

	repo := NewRepository(db)
	ctx := context.Background()

	err = repo.updateRefreshToken(ctx, &userId, &tokens)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestUpdateRefreshToken_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	userId := "e879426c-ad61-4455-b4b4-07ca20aaf410"
	tokens := NewTokens{RefreshToken: "$2a$10$aMjU7t63xeK9gn.oBJgjReAUNG2UJ9/bJ.M0wtWzt/egU0aWynX8q",
		AccessTokenId: "4fa2cf1e-203b-4370-9d9a-6088115799be"}

	query := `INSERT INTO refresh_tokens(user_id, token, access_token_id) VALUES($1, $2, $3) 
				ON CONFLICT (user_id) DO UPDATE SET token = $2, access_token_id = $3, used = false`
	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(userId, tokens.RefreshToken, tokens.AccessTokenId).
		WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	err = repo.updateRefreshToken(ctx, &userId, &tokens)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetUsedRefreshToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"
	rows := sqlmock.NewRows([]string{"used"}).AddRow(true)

	query := `SELECT used FROM refresh_tokens WHERE access_token_id = $1 FOR UPDATE`
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs(accessTokenId).WillReturnRows(rows)

	query = `UPDATE refresh_tokens SET used = true WHERE access_token_id = $1`
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	repo := NewRepository(db)
	ctx := context.Background()
	err = repo.setUsedRefreshToken(ctx, &accessTokenId)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetUsedRefreshToken_BeginTxError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin().WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"
	err = repo.setUsedRefreshToken(ctx, &accessTokenId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetUsedRefreshToken_SelectError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()

	query := `SELECT used FROM refresh_tokens WHERE access_token_id = $1 FOR UPDATE`
	mock.ExpectQuery(regexp.QuoteMeta(query)).WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"
	err = repo.setUsedRefreshToken(ctx, &accessTokenId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetUsedRefreshToken_UpdateError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()

	query := `SELECT used FROM refresh_tokens WHERE access_token_id = $1 FOR UPDATE`
	rows := sqlmock.NewRows([]string{"used"}).AddRow(true)
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"

	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs(accessTokenId).WillReturnRows(rows)

	query = `UPDATE refresh_tokens SET used = true WHERE access_token_id = $1`
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()
	err = repo.setUsedRefreshToken(ctx, &accessTokenId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetUsedRefreshToken_CommitError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()

	query := `SELECT used FROM refresh_tokens WHERE access_token_id = $1 FOR UPDATE`
	rows := sqlmock.NewRows([]string{"used"}).AddRow(true)
	accessTokenId := "4fa2cf1e-203b-4370-9d9a-6088115799be"

	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs(accessTokenId).WillReturnRows(rows)

	query = `UPDATE refresh_tokens SET used = true WHERE access_token_id = $1`
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit().WillReturnError(errors.New("fake error"))

	repo := NewRepository(db)
	ctx := context.Background()

	err = repo.setUsedRefreshToken(ctx, &accessTokenId)
	if err.Error() != "fake error" {
		t.Errorf("unexpected error: %s", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
