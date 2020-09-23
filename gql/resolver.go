package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	 masker "github.com/ggwhite/go-masker"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/ent/user"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
)

type Resolver struct {
	EntClient       *ent.Client
	Config          *api.BootConfig
}
func VerificationCode()(output string){
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	vcode := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	vcode_hash, err := bcrypt.GenerateFromPassword([]byte(vcode), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(vcode_hash)
}
func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (output *api.User, err error) {
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	id := uuid.New()
	if r.Config.AllowSignInWithVerifiedEmailAddress==true {
		_, err = r.EntClient.User.Query().Where(user.Email(*input.UserAttributes[0].Value)).Only(ctx)
		if err !=nil &&ent.IsNotFound(err)==false{
            return 
		}
		if  err==nil {
			errs := fmt.Errorf("Email already exists")
		    return nil, errs

		}
	
		_, err = r.EntClient.User.Create().
		    SetID(id).
		    SetUsername(input.Username).
		    SetPasswordHash(string(password_hash)).
		    SetEmail(*input.UserAttributes[0].Value).
			SetConfirmationCodeHash(VerificationCode()).
			Save(ctx)
			if err != nil {
				return
		    }	
			for i:=1;i<len(input.UserAttributes);i++{
				 _, err = r.EntClient.User.Update(). Where(user.ID(id)).SetPhoneNumber(*input.UserAttributes[i].Value).Save(ctx)
				 if err != nil {
					return
				}	
			}	
			
	        output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: masker.Mobile(*input.UserAttributes[0].Value)}, UserConfirmed: false, UserSub: id.String()}
	        return
	}
	if r.Config.AllowSignInWithVerifiedPhoneNumber==true {
		_, err = r.EntClient.User.Query().Where(user.PhoneNumber(*input.UserAttributes[0].Value)).Only(ctx)
		if err !=nil &&ent.IsNotFound(err)==false{
            return 
		}
		if  err==nil {
			errs := fmt.Errorf("Email already exists")
		    return nil, errs

		}
		_, err = r.EntClient.User.Create().
		    SetID(id).
		    SetUsername(input.Username).
			SetPasswordHash(string(password_hash)).
			SetPhoneNumber(*input.UserAttributes[0].Value).
			SetConfirmationCodeHash(VerificationCode()).
			Save(ctx)
			if err != nil {
				return
		    }	
			for i:=1;i<len(input.UserAttributes);i++{
				_, err = r.EntClient.User.Update(). Where(user.ID(id)).SetEmail(*input.UserAttributes[i].Value).Save(ctx)
				if err != nil {
					return
				}	
			}	
			output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(*input.UserAttributes[0].Value)}, UserConfirmed: false, UserSub: id.String()}
			return
		
	}
	errs := fmt.Errorf("Config is nil")
	return nil, errs

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
