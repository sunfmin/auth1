package tests

import (
	"errors"
	"github.com/sunfmin/auth1/gql/api"
)

var errSendmail =errors.New("graphql: Verification code sending failed")
var userMutationCases = []GraphqlCase{
	{
		name:    "SignUp normal",
		fixture: nil,
		bootConfig: &api.BootConfig{
			AllowSignInWithVerifiedEmailAddress: true,
			AllowSignInWithVerifiedPhoneNumber:  false,
			AllowSignInWithPreferredUsername:    false,
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
							Value: "435418662@qq.com",
						},
						{
							Name:  "phone_number",
							Value: "123",
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
		name:    "InitiateAuth normal",
		fixture: nil,
		query: `
		query InitiateAuth($input:InitiateAuthInput!){
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
			ResendConfirmationCode: true,
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
	},
}
