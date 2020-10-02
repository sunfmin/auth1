package tests

import (
	"fmt"
	"github.com/sunfmin/auth1/gql/api"
)
var vcode=""
func SendMailTest(stuEmail string, subject string, body string) (err error) {
	vcode=body
	fmt.Print("send success")
	return nil
}
func SendMsgTest(tel string, code string) (err error) {
	vcode=code
	fmt.Print("send success")
	return nil
}
var userMutationCases = []GraphqlCase{
	{
		name:    "SignUp normal",
		fixture: nil,
		bootConfig: &api.BootConfig{
			AllowSignInWithVerifiedEmailAddress: true,
			AllowSignInWithVerifiedPhoneNumber:  false,
			AllowSignInWithPreferredUsername:    false,
			SendMailFunc:SendMailTest,
			SendMsgFunc: SendMsgTest,
		},
		query: `
		mutation ($input: SignUpInput!) {
			signUp(input: $input) {
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
					Username: "qwqwq",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "eqwewqeqw",
						},
						{
							Name:  "phone_number",
							Value: "eqwewqeqw",
						},
					},
					Password: "hello",
				},
			},
		},
		expected: &api.Data{
			SignUp: &api.User{},
		},
	},
}
