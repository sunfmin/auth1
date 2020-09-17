package gql

import (
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/sunfmin/auth1/ent"
)

func NewHandler(db *ent.Client, args *Args) (r http.Handler) {
	var graphqlHandler = handler.NewDefaultServer(
		NewExecutableSchema(Config{Resolvers: &Resolver{
			EntClient: db,
			Args:      args,
		}}),
	)

	r = graphqlHandler
	return
}
