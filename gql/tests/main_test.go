package tests

import (
	"context"
	"testing"

	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
	"github.com/sunfmin/auth1/gql/config"
	"github.com/sunfmin/graphql"
	"github.com/theplant/testingutils"
)

type TestDep struct {
	Client    *graphql.Client
	EntClient *ent.Client
}

func ForTest() TestDep {

	return TestDep{
		Client:    config.MustGetGraphqlClient(),
		EntClient: config.MustGetEntClient(),
	}
}

func defaultMatchIgnore(d *api.Data) {
	if d.SignUp != nil {
		d.SignUp.ID = ""
	}
}

type fixtureData func(client *ent.Client)

type Var struct {
	name string
	val  interface{}
}

type GraphqlCase struct {
	name            string
	query           string
	vars            []Var
	expected        *api.Data
	expectedError   error
	fixture         fixtureData
	matchIgnoreFunc func(d *api.Data)
}

func TestLogic(t0 *testing.T) {
	ctx := context.TODO()
	var cases []GraphqlCase
	cases = append(cases, userMutationCases...)

	td := ForTest()
	err := td.EntClient.Schema.Create(ctx)
	if err != nil {
		panic(err)
	}

	for _, c := range cases {
		t0.Run(c.name, func(t *testing.T) {
			if c.fixture != nil {
				c.fixture(td.EntClient)
			}

			req := graphql.NewRequest(c.query)
			for _, va := range c.vars {
				req.Var(va.name, va.val)
			}

			var res = &api.Data{}
			if err := td.Client.Run(ctx, req, res); err != nil {
				if c.expectedError == nil {
					panic(err)
				} else {
					diff := testingutils.PrettyJsonDiff(c.expectedError, err)
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
