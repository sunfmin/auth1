root=$(pwd)
mkdir -p $root/gql/api
cd $root/ent && go run github.com/facebook/ent/cmd/entc generate ./schema &&\
cd $root/gql && go run github.com/99designs/gqlgen &&\
cd $root/gql && gqlgen_data_gen > ./api/data_gen.go && go fmt api/data_gen.go
