root=$(pwd)
cd $root/gql && go run github.com/sunfmin/gqlgen_data_gen > ./api/data_gen.go && go fmt api/data_gen.go
cd $root/ent && go run github.com/facebook/ent/cmd/entc generate ./schema
cd $root/gql && go run github.com/99designs/gqlgen

