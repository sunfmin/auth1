package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/sunfmin/auth1/gql"
	"github.com/sunfmin/auth1/gql/api"
	"github.com/sunfmin/auth1/gql/boot"
)

const defaultPort = "8080"

var vcode = ""

func sendMailTest(stuEmail string, subject string, body string) (err error) {
	vcode = body
	fmt.Print("send success")
	fmt.Print(vcode)
	return nil
}
func sendMsgTest(tel string, code string) (err error) {
	vcode = code
	fmt.Print("send success")
	fmt.Print(vcode)
	return nil
}
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", handler.NewDefaultServer(
		gql.NewExecutableSchema(
			gql.Config{
				Resolvers: gql.NewResolver(
					boot.MustGetEntClient(),
					&api.BootConfig{GitHubOAuth2Config: &api.GitHubOAuth2Config{ClientId: "294f07e8521dce0b96f7", ClientSecret: "74370eb312c2074ce01f2ecb2a9e15b6c80f3db5", AllowedOAuthScopes: "user:email"}, PasswordConfig: &api.PasswordConfig{MinimumLength: 8, RequireNumber: true, RequireSpecialCharacter: true, RequireUppercaseLetters: true, RequireLowercaseLetters: true}, AllowSignInWithVerifiedEmailAddress: true, AllowSignInWithVerifiedPhoneNumber: false, AllowSignInWithPreferredUsername: false, UsernameCaseSensitive: false, EmailConfig: &api.EmailConfig{User: "", Pass: "", Host: "smtp.qq.com", Port: "465"}, PhoneConfig: &api.PhoneConfig{AccessKeyId: "<accesskeyId>", AccessSecret: "<accessSecret>", SignName: "签名", TemplateCode: "模板编码"}},
				),
			},
		)))
	http.HandleFunc("/oauth2/idpresponse", gql.Idpresponse)
	http.HandleFunc("/oauth2/authorize", gql.Authorize)
	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
