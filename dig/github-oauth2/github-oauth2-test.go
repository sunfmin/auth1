package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const htmlIndex = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
</body>
<a href="https://github.com/login/oauth/authorize?client_id=&redirect_uri=http://localhost:8080/oauth2/idpresponse&scope=user:email">Github 第三方授权登录</a>
</body>
</html>
`

type Conf struct {
	ClientId     string
	ClientSecret string
	RedirectUrl  string
}

var conf = Conf{
	ClientId:     "",
	ClientSecret: "",
	RedirectUrl:  "http://localhost:8000/GitHubCallback",
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func Oauth(w http.ResponseWriter, r *http.Request) {

	var err error
	// 获取 code
	var code = r.URL.Query().Get("code")

	// 通过 code, 获取 token
	var tokenAuthUrl = fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", conf.ClientId, conf.ClientSecret, code)
	var token map[string]interface{}
	if token, err = GetToken(tokenAuthUrl); err != nil {
		fmt.Println(err)
		return
	}

	// 通过token，获取用户信息
	var userInfo map[string]interface{}
	if userInfo, err = GetUserInfo(token); err != nil {
		fmt.Println("获取用户信息失败，错误信息为:", err)
		return
	}

	//  将用户信息返回前端
	var userInfoBytes []byte
	if userInfoBytes, err = json.Marshal(userInfo); err != nil {
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(userInfoBytes); err != nil {
		fmt.Println(err)
		return
	}

}
func GetToken(url string) (map[string]interface{}, error) {

	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodPost, url, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")

	var httpClient = http.Client{}
	var res *http.Response
	if res, err = httpClient.Do(req); err != nil {
		return nil, err
	}

	var token = make(map[string]interface{})
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, err
	}
	return token, nil
}

func GetUserInfo(token map[string]interface{}) (map[string]interface{}, error) {

	fmt.Print(token["access_token"])
	var userInfoUrl = "https://api.github.com/user"
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodGet, userInfoUrl, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token["access_token"].(string)))

	var client = http.Client{}
	var res *http.Response
	if res, err = client.Do(req); err != nil {
		return nil, err
	}

	var userInfo = make(map[string]interface{})
	if err = json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

func main() {
	http.HandleFunc("/", Hello)
	http.HandleFunc("/oauth2/idpresponse", Oauth)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println(err)
		return
	}
}