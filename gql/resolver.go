package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"

	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
	"github.com/sunfmin/auth1/ent/user"
)

type Resolver struct {
	EntClient *ent.Client
	Args      *Args
}

func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (user *api.User, err error) {
	id := uuid.New()
	_, err = r.EntClient.User.Create().
		SetPassword(input.Password).
		SetID(id).
		SetUsername(input.Username).
		SetPhoneNumber(input.PhoneNumber).
		SetEmail(input.Email).
		Save(ctx)
	if err != nil {
		return
	}
	user = &api.User{ID: id.String()}
	return
}

func (r *queryResolver) PhoneLogin(ctx context.Context, phone string) ( pwd*api.User, err error) {
	u, err :=  r.EntClient.User.Query().
	   Where(user.PhoneNumber(phone)).
	   	Only(ctx)
	if err != nil {
		return nil,err
	}
	pwd=&api.User{Password: u.Password}
	return pwd,err
}

func (r *queryResolver) EmailLogin(ctx context.Context, email string) (pwd*api.User, err error) {
	u, err :=  r.EntClient.User.Query().
	   Where(user.Email(email)).
	   	Only(ctx)
	if err != nil {
		return nil,err
	}
	pwd=&api.User{Password:u.Password}
	return pwd,err
}

func (r *queryResolver) GetUser(ctx context.Context, accessToken string) ([]*api.User, error) {
	panic("not implemented")
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
