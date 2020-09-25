package tests

import (
	"github.com/sunfmin/auth1/gql/api"
)

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
