package gql

import (
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
)

func NewHandler(db *ent.Client, cfg *api.BootConfig) (r http.Handler) {
	var graphqlHandler = handler.NewDefaultServer(
		NewExecutableSchema(Config{Resolvers: &Resolver{
			EntClient: db,
			Config: cfg,
		}}),
	)

	r = graphqlHandler
	return
}
