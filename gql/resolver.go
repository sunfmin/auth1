package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

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

func HideStar(str string) (result string) {
	if str == "" {
		return "***"
	}
	if strings.Contains(str, "@") {
		res := strings.Split(str, "@")
		if len(res[0]) < 3 {
			resString := "***"
			result = resString + "@" + res[1]
		} else {
			res2 := Substr2(str, 0, 3)
			resString := res2 + "***"
			result = resString + "@" + res[1]
		}
		return result
	} else {
		reg := `^1[0-9]\d{9}$`
		rgx := regexp.MustCompile(reg)
		mobileMatch := rgx.MatchString(str)
		if mobileMatch {
			result = Substr2(str, 0, 3) + "****" + Substr2(str, 7, 11)
		} else {
			nameRune := []rune(str)
			lens := len(nameRune)

			if lens <= 1 {
				result = "***"
			} else if lens == 2 {
				result = string(nameRune[:1]) + "*"
			} else if lens == 3 {
				result = string(nameRune[:1]) + "*" + string(nameRune[2:3])
			} else if lens == 4 {
				result = string(nameRune[:1]) + "**" + string(nameRune[lens-1:lens])
			} else if lens > 4 {
				result = string(nameRune[:2]) + "***" + string(nameRune[lens-2:lens])
			}
		}
		return
	}
}

func Substr2(str string, start int, end int) string {
	rs := []rune(str)
	return string(rs[start:end])
}

func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (output *api.User, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if *input.UserAttributes.Name == "email" {
		id := uuid.New()
		_, err = r.EntClient.User.
			Query().
			Where(user.Email(*input.UserAttributes.Value)).
			Only(ctx)
		if err != nil && err.Error() == "ent: user not found" {
			_, err = r.EntClient.User.
				Create().
				SetUsername(input.Username).
				SetEmail(*input.UserAttributes.Value).
				SetPassword(string(hash)).
				SetID(id).
				Save(ctx)
			if err != nil {
				return
			}
			log.Println("发送验证码")
			result := HideStar(*input.UserAttributes.Value)
			output = &api.User{CodeDeliveryDetails: &api.Details{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: result}, UserConfirmed: false, UserSub: id.String()}
			return
		} else {
			errs := fmt.Errorf("Email already exists")
			return nil, errs
		}
	} else if *input.UserAttributes.Name == "phone_number" {
		id := uuid.New()
		_, err = r.EntClient.User.
			Query().
			Where(user.PhoneNumber(*input.UserAttributes.Value)).
			Only(ctx)
		if err != nil && err.Error() == "ent: user not found" {
			_, err = r.EntClient.User.
				Create().
				SetUsername(input.Username).
				SetPhoneNumber(*input.UserAttributes.Value).
				SetPassword(string(hash)).
				SetID(id).
				Save(ctx)
			if err != nil {
				return
			}
			log.Println("发送验证码")
			result := HideStar(*input.UserAttributes.Value)
			output = &api.User{CodeDeliveryDetails: &api.Details{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: result}, UserConfirmed: false, UserSub: id.String()}
			return
		} else {
			errs := fmt.Errorf("Mobile number already exists")
			return nil, errs
		}
	} else {
		errs := fmt.Errorf("Unknown:Name")
		return nil, errs
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
