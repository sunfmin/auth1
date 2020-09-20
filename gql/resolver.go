package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
    "fmt"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"

)

type Resolver struct {
	EntClient *ent.Client
	Config    *api.BootConfig
}

func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (user *api.User, err error) {
   hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
   if err != nil {
	return
   }

   if *input.UserAttributes.Name=="email"{
	id := uuid.New()
	_, err = r.EntClient.User.
	    Create().
		SetEmail(*input.UserAttributes.Value).
		SetPassword( string(hash)).
		SetID(id).
		Save(ctx)	
	if err != nil {
		return
	}
	user = &api.User{UserConfirmed:true,UserSub: id.String()}
	return
	}else if *input.UserAttributes.Name=="phone_number"{
		id := uuid.New()
		_, err = r.EntClient.User.
		    Create().
		    SetPhoneNumber(*input.UserAttributes.Value).
			SetPassword(string(hash)).
			SetID(id).
			Save(ctx)
		if err != nil {
			return
		}
		user = &api.User{UserConfirmed:true,UserSub: id.String()}
		return
	 }else{
		    err:=fmt.Errorf("Unknown:Name")
            return nil,err
	 }
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
