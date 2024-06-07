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

func (r *repository) getUserById(ctx context.Context, id string) (user User, err error) {

	query := "SELECT id, password FROM users WHERE id = $1"
	err = r.db.QueryRowContext(ctx, query, id).Scan(&user.Id, &user.Password)
	if err != nil {
		return User{}, err
	}

	return
}
