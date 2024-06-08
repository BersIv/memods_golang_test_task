package auth

import (
	"context"
	"database/sql"
)

type repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) Repository {
	return &repository{db: db}
}

func (r *repository) getUserById(ctx context.Context, userId *string) (*User, error) {
	var user User
	query := `SELECT id, username, password FROM users WHERE id = $1`
	err := r.db.QueryRowContext(ctx, query, userId).Scan(&user.Id, &user.Username, &user.Password)
	if err != nil {
		return &User{}, err
	}

	return &user, nil
}

func (r *repository) getRefreshToken(ctx context.Context, accessTokenId *string) (*string, error) {
	var token string
	query := "SELECT token FROM refresh_tokens WHERE access_token_id = $1"
	err := r.db.QueryRowContext(ctx, query, accessTokenId).Scan(&token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *repository) updateRefreshToken(ctx context.Context, userId *string, tokens *NewTokens) error {

	query := `INSERT INTO refresh_tokens(user_id, token, access_token_id) VALUES($1, $2, $3) 
				ON CONFLICT (user_id) DO UPDATE SET token = $2, access_token_id = $3`
	_, err := r.db.Exec(query, userId, tokens.RefreshToken, tokens.AccessTokenId)
	if err != nil {
		return err
	}

	return nil
}
