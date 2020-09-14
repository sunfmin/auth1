package config

import (
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql"
	"github.com/sunfmin/graphql"
	"github.com/sunfmin/handlertransport"
)

var _entClient *ent.Client

func MustGetEntClient() *ent.Client {
	if _entClient != nil {
		return _entClient
	}

	var err error
	_entClient, err = ent.Open("postgres", os.Getenv("DB"))

	if err != nil {
		panic(err)
	}
	return _entClient
}

func UseGoLog(c *graphql.Client) {
	c.Log = func(s string) {
		log.Println(s)
	}
}

var _client *graphql.Client

func MustGetGraphqlClient() *graphql.Client {
	if _client != nil {
		return _client
	}

	var graphqlHandler = gql.NewHandler(MustGetEntClient())

	_client = graphql.NewClient("",
		UseGoLog,
		graphql.WithHTTPClient(&http.Client{Transport: handlertransport.New(graphqlHandler)}),
	)

	return _client
}
