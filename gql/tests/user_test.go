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
	token := TestAccessToken
	return token,nil
}
func CreateAccessToken(name string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * 3600).Unix(),
	})

	return token.SignedString([]byte("welcomelogin"))
}

var TestAccessToken,err = CreateAccessToken("test")

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
			CreateAccessTokenFunc: CreateAccessTokenTest,
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
		name:    "InitiateAuth the user is not activated",
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
		expectedError: "graphql: The user is not activated",
	},{
		name:    "ConfirmSignUp timeout",
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
					ConfirmationCode: "000000",
				},
			},
		},
		expectedError: "graphql: Captcha timeout",
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
		name:    "ChangePassword token is invalid",
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
					AccessToken: TestAccessToken,
					PreviousPassword: "test",
					ProposedPassword: "test",
				},
			},
		},
		expectedError: "graphql: Token is invalid",
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
		name:    "ChangePassword accesstoken is nil",
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
					AccessToken: "",
					PreviousPassword: "test",
					ProposedPassword: "test",
				},
			},
		},
		expectedError: "graphql: AccessToken is nil",
	},{
		name:    "ChangePassword wrong previouspassword",
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
					AccessToken: TestAccessToken,
					PreviousPassword: "test_wrong_password",
					ProposedPassword: "test",
				},
			},
		},
		expectedError: "graphql: Wrong PreviousPassword",
	},{
		name:    "ChangePassword password no change",
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
					AccessToken: TestAccessToken,
					PreviousPassword: "test",
					ProposedPassword: "test",
				},
			},
		},
		expectedError: "graphql: The new password cannot be the same as the old password",
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
					AccessToken: TestAccessToken,
					PreviousPassword: "test",
					ProposedPassword: "newtest",
				},
			},
		},
		expected: &api.Data{
			ChangePassword: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},{
		name:    "ForgotPassword account does not exist",
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
					Username: "test_not_exist",
				},
			},
		},
		expectedError: "graphql: Account does not exist",
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
		name:    "InitiateAuth AuthFlow is nil",
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
					AuthFlow: "",
					AuthParameters: &api.AuthParameters{
						Username: "test",
						Password: "test",
					},
				},
			},
		},
		expectedError: "graphql: AuthFlow is nil",
	},{
		name:    "InitiateAuth Unknown AuthFlow",
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
					AuthFlow: "test",
					AuthParameters: &api.AuthParameters{
						Username: "test",
						Password: "test",
					},
				},
			},
		},
		expectedError: "graphql: Unknown AuthFlow",
	},{
		name:    "InitiateAuth User Not Found",
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
						Username: "test_unkonw",
						Password: "test",
					},
				},
			},
		},
		expectedError: "graphql: ent: user not found",
	},{
		name:    "InitiateAuth Wrong Password",
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
						Password: "test_wrong_password",
					},
				},
			},
		},
		expectedError: "graphql: crypto/bcrypt: hashedPassword is not the hash of the given password",
	},{
		name:    "GlobalSignOut normal",
		fixture: nil,
		query: `
		mutation ($input:GlobalSignOutInput!){
		  GlobalSignOut(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.GlobalSignOutInput{
					AccessToken: TestAccessToken,
				},
			},
		},
		expected: &api.Data{
			GlobalSignOut:&api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	},
}