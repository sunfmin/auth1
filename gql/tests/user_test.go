package tests

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sunfmin/auth1/gql/api"
	"time"
)

func CreateTestCode() string {
	code := "111111"
	return code
}
func SendMailTest(stuEmail string, subject string, body string) (err error) {
	fmt.Printf("send success")
	return nil
}
func SendMsgTest(tel string, code string) (err error) {
	fmt.Print("send success")
	return nil
}
func CreateAccessTokenTest(name string) (string, error) {
	token := fakeAccessToken
	return token,nil
}
func CreateAccessToken(name string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * 3600).Unix(),
	})

	return token.SignedString([]byte("welcomelogin"))
}

var fakeAccessToken,err = CreateAccessToken("test")

var userMutationCases = []GraphqlCase{
	{
		name:    "SignUp normal",
		fixture: nil,
		bootConfig: &api.BootConfig{
			AllowSignInWithVerifiedEmailAddress: true,
			AllowSignInWithVerifiedPhoneNumber: false,
			AllowSignInWithPreferredUsername: false,
			SendMailFunc: SendMailTest,
			SendMsgFunc: SendMsgTest,
			CreateAccessToken: CreateAccessTokenTest,
			CreateCodeFunc: CreateTestCode,
		},
		query: `
		mutation ($input: SignUpInput!) {
			SignUp(input: $input) {
				CodeDeliveryDetails{
					AttributeName,
					DeliveryMedium,
					Destination
				  },
			   UserConfirmed, 
                  UserSub
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "test",
				},
			},
		},
		expected: &api.Data{
			SignUp: &api.User{
				CodeDeliveryDetails: &api.CodeDeliveryDetails{
					AttributeName: "",
					DeliveryMedium: "",
					Destination: "",
				},
			},
		},
	},{
		name:    "ConfirmSignUp normal",
		fixture: nil,
		query: `
		mutation ConfirmSignUp($input:ConfirmSignUpInput!){
		  ConfirmSignUp(input:$input){
					ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username: "test",
					ConfirmationCode: "111111",
				},
			},
		},
		expected: &api.Data{
			ConfirmSignUp: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},{
		name:    "InitiateAuth normal",
		fixture: nil,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: &api.AuthParameters{
						Username: "test",
						Password: "test",
					},
				},
			},
		},
		expected: &api.Data{
			InitiateAuth: &api.AuthenticationResult{
				ExpiresIn: 3600,
			},
		},
	},{
		name:    "ForgotPassword normal",
		fixture: nil,
		query: `
		mutation ($input:ForgotPasswordInput!){
		  ForgotPassword(input:$input){
			AttributeName,
			DeliveryMedium,
			Destination
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ForgotPasswordInput{
					Username: "test",
				},
			},
		},
		expected: &api.Data{
			ForgotPassword:&api.CodeDeliveryDetails{},
		},
	},{
		name:    "ConfirmForgotPassword normal",
		fixture: nil,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
		  ConfirmForgotPassword(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username: "test",
					ConfirmationCode: "111111",
					Password: "test",
				},
			},
		},
		expected: &api.Data{
			ConfirmForgotPassword:&api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},{
		name:    "ResendConfirmationCode normal",
		fixture: nil,
		query: `
		mutation ($input:ResendConfirmationCodeInput!){
		  ResendConfirmationCode(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ResendConfirmationCodeInput{
					Username: "test",
				},
			},
		},
		expected: &api.Data{
			ResendConfirmationCode: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},{
		name:    "ChangePassword normal",
		fixture: nil,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken: fakeAccessToken,
					PreviousPassword: "test",
					ProposedPassword: "test",
				},
			},
		},
		expected: &api.Data{
			ChangePassword: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},
}
