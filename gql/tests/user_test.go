package tests

import (
	"errors"
	"fmt"

	"github.com/sunfmin/auth1/gql/api"
)

type Code struct {
	Vcode string
}

var c Code

func SendMailTest(stuEmail string, subject string, body string) (err error) {
	c.Vcode = body
	fmt.Print("send success")
	fmt.Print(c.Vcode)
	return nil
}
func SendMsgTest(tel string, code string) (err error) {
	c.Vcode = code
	fmt.Print("send success")
	fmt.Print(c.Vcode)
	return nil
}
func SendCode() string {
	fmt.Print("send")
	fmt.Print(c.Vcode)
	return c.Vcode
}

var errSendmail = errors.New("graphql: Verification code sending failed")

var userMutationCases = []GraphqlCase{
	{
		name:    "SignUp normal",
		fixture: nil,
		bootConfig: &api.BootConfig{
			AllowSignInWithVerifiedEmailAddress: true,
			AllowSignInWithVerifiedPhoneNumber:  false,
			AllowSignInWithPreferredUsername:    false,
			SendMailFunc:                        SendMailTest,
			SendMsgFunc:                         SendMsgTest,
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
					AttributeName:  "",
					DeliveryMedium: "",
					Destination:    "",
				},
			},
		},
	}, {
		name:    "ConfirmSignUp normal",
		fixture: nil,
		bootConfig: &api.BootConfig{
			AllowSignInWithVerifiedEmailAddress: true,
			AllowSignInWithVerifiedPhoneNumber:  false,
			AllowSignInWithPreferredUsername:    false,
			SendMailFunc:                        SendMailTest,
			SendMsgFunc:                         SendMsgTest,
		},
		query: `
		mutation ConfirmSignUp($input:ConfirmSignUpInput!){
		  ConfirmSignUp(input:$input)
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username:         "test",
					ConfirmationCode: SendCode(),
				},
			},
		},
		expected: &api.Data{
			ConfirmSignUp: "true",
		},
	}, /*{
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
			name:    "ResendConfirmationCode normal",
			fixture: nil,
			query: `
			mutation ($input:ResendConfirmationCodeInput!){
			  ResendConfirmationCode(input:$input)
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
				ResendConfirmationCode: "true",
			},
		},{
			name:    "MailSend error",
			fixture: nil,
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
						Username: "test_sendEmail",
						UserAttributes: []*api.AttributeType{
							{
								Name:  "email",
								Value: "test_sendEmail",
							},
							{
								Name:  "phone_number",
								Value: "test_sendEmail",
							},
						},
						Password: "test",
					},
				},
			},
			expectedError: errSendmail.Error(),
		},*/
}
