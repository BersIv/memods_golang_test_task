package auth

import "context"

type User struct {
	Id       string `json:"Id"`
	Password string `json:"Password"`
}

type Repository interface {
	getUserById(ctx context.Context, id string) (user User, err error)
}
