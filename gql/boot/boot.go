package boot

import (
	_ "github.com/lib/pq"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql"
	"github.com/sunfmin/auth1/gql/api"
	"github.com/sunfmin/graphql"
	"github.com/sunfmin/handlertransport"
	"log"
	"net/http"
)

var _entClient *ent.Client

func MustGetEntClient() *ent.Client {
	if _entClient != nil {
		return _entClient
	}

	var err error
	_entClient, err = ent.Open("postgres", "host=localhost port=5432 user=auth1 dbname=auth1_test password=123 sslmode=disable")

	if err != nil {
		panic(err)
	}
	return _entClient
}

func NewGraphqlClient(cfg *api.BootConfig) *graphql.Client {
	var graphqlHandler = gql.NewHandler(MustGetEntClient(), cfg)
	_client = graphql.NewClient("",
		UseGoLog,
		graphql.WithHTTPClient(&http.Client{Transport: handlertransport.New(graphqlHandler)}),
	)
	return _client
}

func UseGoLog(c *graphql.Client) {
	c.Log = func(s string) {
		log.Println(s)
	}
}

var _client *graphql.Client

func MustGetGraphqlClient(cfg *api.BootConfig) *graphql.Client {
	if _client != nil {
		return _client
	}

	if cfg == nil {
		cfg = &api.BootConfig{}
	}

	_client = NewGraphqlClient(cfg)
	return _client
}
