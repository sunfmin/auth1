package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
	masker "github.com/ggwhite/go-masker"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/ent/user"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
)

type Resolver struct {
	EntClient *ent.Client
	Config    *api.BootConfig
}

const (
	JwtSecretKey                = "welcomelogin"
	JwtExpireSecond             = 3600
	EmailAttributeName          = "email"
	PhoneNumberAttributeName    = "phone_number"
	refreshtokenJwtSecretKey    = "refreshtoken"
	refreshtokenJwtExpireSecond = 2592000
)

func VerificationCode() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	return code
}
func CreateAccessToken(name string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * JwtExpireSecond).Unix(),
	})

	return token.SignedString([]byte(JwtSecretKey))
}
func CreateIdToken(id string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"ID":  id,
		"exp": time.Now().Add(time.Second * JwtExpireSecond).Unix(),
	})

	return token.SignedString([]byte(JwtSecretKey))
}
func CreateRefreshToken(id string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": id,
		"exp":      time.Now().Add(time.Second * refreshtokenJwtExpireSecond).Unix(),
	})

	return token.SignedString([]byte(refreshtokenJwtSecretKey))
}
func ParseJwtToken(s string) (jwt.MapClaims, error) {
	fn := func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtSecretKey), nil
	}
	result, error := jwt.Parse(s, fn)
	if error != nil {
		return nil, error
	}
	finToken := result.Claims.(jwt.MapClaims)
	return finToken, nil
}
func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (output *api.User, err error) {
	if r.Config.AllowSignInWithVerifiedEmailAddress && r.Config.AllowSignInWithVerifiedPhoneNumber {
		err = fmt.Errorf("verify email address and verify phone number can not be true the same time")
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress == false && r.Config.AllowSignInWithVerifiedPhoneNumber == false {
		err = fmt.Errorf("verify email address and verify phone number can not be false the same time")
		return
	}
	var (
		email       string
		phonenumber string
	)
	id := uuid.New()
	code := VerificationCode()
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	for i := 0; i < len(input.UserAttributes); i++ {
		switch {
		case input.UserAttributes[i].Name == EmailAttributeName:
			email = input.UserAttributes[i].Value
		case input.UserAttributes[i].Name == PhoneNumberAttributeName:
			phonenumber = input.UserAttributes[i].Value
		default:
		}
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(input.Username).
			SetPasswordHash(string(password_hash)).
			SetEmail(email).
			SetPhoneNumber(phonenumber).
			SetConfirmationCodeHash(string(code_hash)).
			SetUserAttributes(input.UserAttributes).
			Save(ctx)
		if err != nil {
			return
		}
		if r.Config.SendMailFunc(email, "邮箱验证码", code) != nil {
			err := fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: EmailAttributeName, DeliveryMedium: "EMAIL", Destination: masker.Mobile(email)}, UserConfirmed: false, UserSub: id.String()}
		return
	}
	if r.Config.AllowSignInWithVerifiedPhoneNumber {
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(input.Username).
			SetPasswordHash(string(password_hash)).
			SetPhoneNumber(phonenumber).
			SetEmail(email).
			SetConfirmationCodeHash(string(code_hash)).
			SetUserAttributes(input.UserAttributes).
			Save(ctx)
		if err != nil {
			return
		}
		if r.Config.SendMsgFunc(phonenumber, code) != nil {
			err := fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: PhoneNumberAttributeName, DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(phonenumber)}, UserConfirmed: false, UserSub: id.String()}
		return

	}
	err = fmt.Errorf("verify email address and verify phone number can not be nil")
	return

}
func (r *queryResolver) ConfirmSignUp(ctx context.Context, input api.ConfirmSignUpInput) (output bool, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		output = false
		return output, nil
	}
	output = true
	return
}
func (r *queryResolver) InitiateAuth(ctx context.Context, input api.InitiateAuthInput) (output *api.AuthenticationResult, err error) {
	if input.AuthFlow == "" {
		err = fmt.Errorf("AuthFlow is nil")
		return nil, err
	}
	if input.AuthFlow != "USER_PASSWORD_AUTH" && input.AuthFlow != "EMAIL_PASSWORD_AUTH" && input.AuthFlow != "PHONENUMBER_PASSWORD_AUTH" {
		err = fmt.Errorf("Unknow AuthFlow")
		return nil, err

	}
	if input.AuthFlow == "USER_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Username(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(u.Username)
		Idtoken, err := CreateIdToken(u.ID.String())
		RefreshToken, err := CreateRefreshToken(u.Username)
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
		return output, nil
	}
	if input.AuthFlow == "EMAIL_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Email(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(u.Username)
		Idtoken, err := CreateIdToken(u.ID.String())
		RefreshToken, err := CreateRefreshToken(u.Username)
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
		return output, nil
	}
	u, err := r.EntClient.User.Query().Where(user.PhoneNumber(input.AuthParameters.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
	if err != nil {
		return
	}
	AccessToken, err := CreateAccessToken(u.Username)
	Idtoken, err := CreateIdToken(u.ID.String())
	RefreshToken, err := CreateRefreshToken(u.Username)
	output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
	return
}
func (r *queryResolver) GetUser(ctx context.Context, accessToken string) ([]*api.User, error) {
	panic("not implemented")
}
func (r *mutationResolver) ChangePassword(ctx context.Context, input api.ChangePasswordInput) (output bool, err error) {
	if input.AccessToken == "" {
		err := fmt.Errorf("AccessToken is nil")
		return false, err
	}
	result, err := ParseJwtToken(input.AccessToken)
	if err != nil {
		return
	}
	u, err := r.EntClient.User.Query().Where(user.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.PreviousPassword))
	if err != nil {
		return
	}
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.ProposedPassword), bcrypt.DefaultCost)
	_, err = r.EntClient.User.Update().Where(user.Username(result["Username"].(string))).SetPasswordHash(string(password_hash)).Save(ctx)
	if err != nil {
		return
	}
	return true, nil
}
func (r *mutationResolver) ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) (output *api.CodeDeliveryDetails, err error) {
	if r.Config.AllowSignInWithVerifiedEmailAddress && r.Config.AllowSignInWithVerifiedPhoneNumber {
		err = fmt.Errorf("Config is all true")
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress == false && r.Config.AllowSignInWithVerifiedPhoneNumber == false {
		err = fmt.Errorf("Config is all false")
		return
	}
	code := VerificationCode()
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		if r.Config.SendMailFunc(u.Email, "邮箱验证码", code) != nil {
			err = fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).Save(ctx)
		if err != nil {
			return nil, err
		}
		return &api.CodeDeliveryDetails{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: masker.Mobile(u.Email)}, nil
	}
	if r.Config.AllowSignInWithVerifiedPhoneNumber {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		if r.Config.SendMsgFunc(u.PhoneNumber, code) != nil {
			err = fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).Save(ctx)
		if err != nil {
			return nil, err
		}
		return &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(u.PhoneNumber)}, nil
	}
	err = fmt.Errorf("Config is nil")
	return
}
func (r *mutationResolver) ResendConfirmationCode(ctx context.Context, input api.ResendConfirmationCodeInput) (output bool, err error) {
	if r.Config.AllowSignInWithVerifiedEmailAddress && r.Config.AllowSignInWithVerifiedPhoneNumber {
		err = fmt.Errorf("Config is all true")
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress == false && r.Config.AllowSignInWithVerifiedPhoneNumber == false {
		err = fmt.Errorf("Config is all false")
		return
	}
	code := VerificationCode()
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			return false, err
		}
		if r.Config.SendMailFunc(u.Email, "邮箱验证码", code) != nil {
			errs := fmt.Errorf("Verification code sending failed")
			return false, errs
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).Save(ctx)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	if r.Config.AllowSignInWithVerifiedPhoneNumber {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			return false, err
		}
		if r.Config.SendMsgFunc(u.PhoneNumber, code) != nil {
			err = fmt.Errorf("Verification code sending failed")
			return false, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).Save(ctx)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	err = fmt.Errorf("Config is nil")
	return
}
func (r *mutationResolver) ConfirmForgotPassword(ctx context.Context, input api.ConfirmForgotPasswordInput) (output bool, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		return
	}
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetPasswordHash(string(password_hash)).Save(ctx)
	if err != nil {
		return
	}
	output = true
	return
}
func (r *queryResolver) GlobalSignOut(ctx context.Context, input api.GlobalSignOutInput) (bool, error) {
	return true, nil
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
