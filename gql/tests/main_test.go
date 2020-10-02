package tests

import (
	"context"
	"testing"

	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
	"github.com/sunfmin/auth1/gql/boot"
	"github.com/sunfmin/graphql"
	"github.com/theplant/testingutils"
)

func defaultMatchIgnore(d *api.Data) {
	if d.SignUp != nil {
		d.SignUp.UserSub = ""
		d.SignUp.UserConfirmed = false
		d.SignUp.CodeDeliveryDetails.AttributeName = ""
		d.SignUp.CodeDeliveryDetails.DeliveryMedium = ""
		d.SignUp.CodeDeliveryDetails.Destination = ""
	}
	if d.InitiateAuth != nil {
		d.InitiateAuth.AccessToken = ""
		d.InitiateAuth.ExpiresIn = 3600
		d.InitiateAuth.IDToken = ""
		d.InitiateAuth.RefreshToken = ""
		d.InitiateAuth.TokenType = ""
	}
	if d.ForgotPassword != nil {
		d.ForgotPassword.AttributeName = ""
		d.ForgotPassword.DeliveryMedium = ""
		d.ForgotPassword.Destination = ""
	}
}

type fixtureData func(client *ent.Client)

type Var struct {
	name string
	val  interface{}
}

type GraphqlCase struct {
	name            string
	bootConfig      *api.BootConfig
	query           string
	vars            []Var
	expected        *api.Data
	expectedError   string
	fixture         fixtureData
	matchIgnoreFunc func(d *api.Data)
}

func TestLogic(t0 *testing.T) {
	ctx := context.TODO()
	var cases []GraphqlCase
	cases = append(cases, userMutationCases...)

	entClient := boot.MustGetEntClient()
	err := entClient.Schema.Create(ctx)
	if err != nil {
		panic(err)
	}

	for _, c := range cases {
		t0.Run(c.name, func(t *testing.T) {
			client := boot.MustGetGraphqlClient(c.bootConfig)
			if c.fixture != nil {
				c.fixture(entClient)
			}

			req := graphql.NewRequest(c.query)
			for _, va := range c.vars {
				req.Var(va.name, va.val)
			}

			var res = &api.Data{}
			if err := client.Run(ctx, req, res); err != nil {
				if c.expectedError == "" {
					panic(err)
				} else {
					diff := testingutils.PrettyJsonDiff(c.expectedError, err.Error())
					if len(diff) > 0 {
						t.Error(diff)
					}
				}
				return
			}

			ig := c.matchIgnoreFunc
			if c.matchIgnoreFunc == nil {
				ig = defaultMatchIgnore
			}

			ig(res)

			diff := testingutils.PrettyJsonDiff(c.expected, res)
			if len(diff) > 0 {
				t.Error(diff)
			}
		})
	}
}
