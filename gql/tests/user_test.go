package tests

import (
	"github.com/sunfmin/auth1/gql/api"
)

var userMutationCases = []GraphqlCase{
	{
		name:    "SignUp normal",
		fixture: nil,
		Config: &api.BootConfig{
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
					Username:"qwqwq",
					UserAttributes:[{
						AttributeType.Name:"email",
						AttributeType.Value:"eqwewqeqw",
					},{
						AttributeType.Name:"email",
						AttributeType.Value:"eqwewqeqw",
					},]
					Password: "hello",
				},
			},
		},
		expected: &api.Data{
			SignUp: &api.User{},
		},
	},
}
