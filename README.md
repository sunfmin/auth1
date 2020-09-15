to run tests

1. `./generate.sh` to generate the ent files, and gql files
2. `docker-compose up` to start the database
3. `source dev_env` to load the db connection string
4. `go test -v ./gql/...` to run tests to see if tests pass

to run graphql playground

1. `source dev_env` to load the db connection string
2. `go run ./gql/server/` to start the server
3. Open http://localhost:8080/
