package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
)

const htmlIndex = `<html><body>
<a href="/Login">Log in with Github or Amazon</a>
</body></html>
`

//amazon endpoint
/*var endPoint = oauth2.Endpoint{
	AuthURL:  "https://www.amazon.com/ap/oa",
	TokenURL: "https://api.amazon.com/auth/o2/token",
}*/
//github endpoint
var endPoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

var googleOauthConfig = &oauth2.Config{
	ClientID:     "",
	ClientSecret: "",
	RedirectURL:  "",
	Scopes:       []string{""},
	Endpoint:     endPoint,
}

const oauthStateString = "random"

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/Login", handleGoogleLogin)
	http.HandleFunc("/Callback", handleGoogleCallback)
	fmt.Println(http.ListenAndServe(":9090", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	fmt.Println("url" + url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Println("state:" + state)

	code := r.FormValue("code")
	fmt.Println("code:" + code)
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Println("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Println("token:" + token.AccessToken)

	//github getting userinfo
	var client = http.Client{}
	var userInfoUrl = "https://api.github.com/user"
	r, err = http.NewRequest(http.MethodGet, userInfoUrl, nil)
	if err != nil {
		return
	}
	r.Header.Set("accept", "application/json")
	r.Header.Set("Authorization", fmt.Sprintf("token %s", token.AccessToken))
	response, err := client.Do(r)
	if err != nil {
		return
	}
	//amazon get userinfo
	//response, err := http.Get("https://api.github.com/user?access_token=" + token.AccessToken)

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	fmt.Fprintf(w, "Content: %s\n", contents)
}
