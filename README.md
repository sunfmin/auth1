to run tests

1. `./generate.sh` to generate the ent files, and gql files
2. `docker-compose up` to start the database
3. `source dev_env` to load the db connection string
4. `go test -v ./gql/...` to run tests to see if tests pass

to run graphql playground

1. `source dev_env` to load the db connection string
2. `go run ./gql/server/` to start the server
3. Open http://localhost:8080/

win10 to run tests

1. ` export PATH=(这里填自己go bin的文件位置):$PATH` open git bash in project and run it(如果不懂得go bin的位置可以运行go env查看)
2. `./generate.sh` to generate the ent files, and gql files
3. create POSTGRESQL and POSTGRES_USER=auth1 POSTGRES_PASSWORD=123 POSTGRES_DB=auth1_test
4. `source dev_env` to load the db connection string 
5. `go test -v ./gql/...` to run tests to see if tests pass