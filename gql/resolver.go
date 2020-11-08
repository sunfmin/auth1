package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"github.com/dgrijalva/jwt-go"
	masker "github.com/ggwhite/go-masker"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/ent/socialaccount"
	"github.com/sunfmin/auth1/ent/user"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

type Resolver struct {
	EntClient *ent.Client
	Config    *api.BootConfig
}

var (
	githubconfig *api.GitHubOAuth2Config
)

const (
	EmailAttributeName       = "email"
	PhoneNumberAttributeName = "phone_number"
	timeLayout               = "2006-01-02 15:04:05"
)

func UserNameCaseSensitive(r *api.BootConfig, userName string) string {
	if r.UsernameCaseSensitive {
		return userName
	}
	return strings.ToLower(userName)
}

func NewResolver(entClient *ent.Client, config *api.BootConfig) (r *Resolver) {
	if config.SendMailFunc == nil {
		config.SendMailFunc = defaultSendMail
	}
	if config.SendMsgFunc == nil {
		config.SendMsgFunc = defaultSendMsg
	}
	if config.CreateAccessTokenFunc == nil {
		config.CreateAccessTokenFunc = createAccessToken
	}
	if config.JwtTokenConfig == nil {
		config.JwtTokenConfig = &api.JwtTokenConfig{JwtSecretKey: "welcomelogin", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "refreshtoken", RefreshTokenJwtExpireSecond: 2592000}
	}
	if config.EmailConfig == nil {
		panic("SendEmailConfig is nil")
	}
	if config.PhoneConfig == nil {
		panic("SendPhoneConfig is nil")
	}
	if config.PasswordConfig == nil {
		panic("PasswordConfig is nil")
	}
	if config.AllowSignInWithGitHubOAuth2 == true {
		if config.GitHubOAuth2Config == nil {
			panic("GitHubOAuth2Config is nil")
		}
		githubconfig = config.GitHubOAuth2Config
	}
	if config.AllowSignInWithVerifiedEmailAddress && config.AllowSignInWithVerifiedPhoneNumber {
		panic("verify email address and verify phone number can not be true the same time")
	}
	if !config.AllowSignInWithVerifiedEmailAddress && !config.AllowSignInWithVerifiedPhoneNumber {
		panic("verify email address and verify phone number can not be false the same time")
	}
	r = &Resolver{EntClient: entClient, Config: config}
	return
}

func Authorize(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("response_type") == "code" {
		if r.URL.Query().Get("identity_provider") == "GitHub" {
			url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s&state=%s", githubconfig.ClientId, githubconfig.DefaultRedirectURI, githubconfig.AllowedOAuthScopes, r.URL.Query().Get("redirect_uri"))
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		}
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?error=invalid_reques", http.StatusTemporaryRedirect)
	}
	http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?error=invalid_reques", http.StatusTemporaryRedirect)
}

func Idpresponse(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectUri := r.URL.Query().Get("state")
	http.Redirect(w, r, redirectUri+"?"+code, http.StatusTemporaryRedirect)
}
func getToken(code string) (map[string]interface{}, error) {
	tokenAuthUrl := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", githubconfig.ClientId, githubconfig.ClientSecret, code)
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodPost, tokenAuthUrl, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	var httpClient = http.Client{}
	var res *http.Response
	if res, err = httpClient.Do(req); err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		err = fmt.Errorf("get failed")
		return nil, err
	}
	var token = make(map[string]interface{})
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, err
	}
	if token["error"] != nil {
		err = fmt.Errorf(token["error"].(string))
		return nil, err
	}
	return token, nil
}

func getUserInfo(token string) (map[string]interface{}, error) {

	var userInfoUrl = "https://api.github.com/user"
	var req *http.Request
	var err error
	if req, err = http.NewRequest(http.MethodGet, userInfoUrl, nil); err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	var client = http.Client{}
	var res *http.Response
	if res, err = client.Do(req); err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		err = fmt.Errorf("get failed")
		return nil, err
	}
	var userInfo = make(map[string]interface{})
	if err = json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	if userInfo["error"] != nil {
		err = fmt.Errorf(userInfo["error"].(string))
		return nil, err
	}
	return userInfo, nil
}

func VerifyPwd(password string, passwordConfig *api.PasswordConfig) (err error) {
	num := `[0-9]{1}`
	a_z := `[a-z]{1}`
	A_Z := `[A-Z]{1}`
	symbol := `[!@#~$%^&*()+|_]{1}`
	if password == "" {
		err = api.ErrPasswordEmpty
		return
	}
	if len(password) < passwordConfig.MinimumLength {
		err = api.ErrPasswordTooShort
		return
	}
	if passwordConfig.RequireNumber {
		if b, err := regexp.MatchString(num, password); !b || err != nil {
			err = api.ErrPasswordNumber
			return err
		}
	}
	if passwordConfig.RequireSpecialCharacter {
		if b, err := regexp.MatchString(symbol, password); !b || err != nil {
			err = api.ErrPasswordSpecialCharacter
			return err
		}
	}
	if passwordConfig.RequireUppercaseLetters {
		if b, err := regexp.MatchString(A_Z, password); !b || err != nil {
			err = api.ErrPasswordUppercaseLetters
			return err
		}
	}
	if passwordConfig.RequireLowercaseLetters {
		if b, err := regexp.MatchString(a_z, password); !b || err != nil {
			err = api.ErrPasswordLowercaseLetters
			return err
		}
	}
	return nil
}

func nowTime() string {
	timeUnix := time.Now().Unix()
	formatTimeStr := time.Unix(timeUnix, 0).Format(timeLayout)
	return formatTimeStr
}

func timeSub(input string) (err error) {
	local, _ := time.LoadLocation("Local")
	theTime, _ := time.ParseInLocation(timeLayout, input, local)
	TimeNow := time.Now()
	left := TimeNow.Sub(theTime)
	if left.Seconds() > 300 {
		err = api.ErrCaptchaTimeout
		return
	}
	return
}

func verificationCode() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	return code
}

func defaultSendMail(EmailConfig *api.EmailConfig, stuEmail string, subject string, body string) (err error) {
	mailTo := []string{stuEmail}
	port, _ := strconv.Atoi(EmailConfig.Port)

	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(EmailConfig.User, "验证码"))
	m.SetHeader("To", mailTo...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(EmailConfig.Host, port, EmailConfig.User, EmailConfig.Pass)
	err = d.DialAndSend(m)
	if err != nil {
		return
	}
	return
}

func defaultSendMsg(PhoneConfig *api.PhoneConfig, tel string, code string) (err error) {
	client, err := dysmsapi.NewClientWithAccessKey("cn-hangzhou", PhoneConfig.AccessKeyId, PhoneConfig.AccessSecret)
	request := dysmsapi.CreateSendSmsRequest()
	request.Scheme = "https"
	request.PhoneNumbers = tel                      //手机号变量值
	request.SignName = PhoneConfig.SignName         //签名
	request.TemplateCode = PhoneConfig.TemplateCode //模板编码
	request.TemplateParam = "{\"code\":\"" + code + "\"}"
	response, err := client.SendSms(request)
	if response.Code == "isv.BUSINESS_LIMIT_CONTROL" {
		err = fmt.Errorf("frequency_limit")
		return
	}
	if err != nil {
		err = fmt.Errorf("failed")
		return
	}
	return
}

func createAccessToken(JwtTokenConfig *api.JwtTokenConfig, name string, idp string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"Idp":      idp,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.JwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.JwtSecretKey))
}

func createIdToken(JwtTokenConfig *api.JwtTokenConfig, id string, idp string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"ID":  id,
		"Idp": idp,
		"exp": time.Now().Add(time.Second * time.Duration(JwtTokenConfig.JwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.JwtSecretKey))
}

func createRefreshToken(JwtTokenConfig *api.JwtTokenConfig, name string, idp string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"Idp":      idp,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.RefreshTokenJwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.RefreshTokenJwtSecretKey))
}

func parseJwtToken(JwtTokenConfig *api.JwtTokenConfig, token string, tokentype string) (jwt.MapClaims, error) {
	var key jwt.Keyfunc
	if tokentype == "access" {
		key = func(token *jwt.Token) (interface{}, error) {
			return []byte(JwtTokenConfig.JwtSecretKey), nil
		}
	}
	if tokentype == "refresh" {
		key = func(token *jwt.Token) (interface{}, error) {
			return []byte(JwtTokenConfig.RefreshTokenJwtSecretKey), nil
		}
	}
	result, error := jwt.Parse(token, key)
	if error != nil {
		return nil, error
	}
	finToken := result.Claims.(jwt.MapClaims)
	return finToken, nil
}

func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (output *api.User, err error) {
	var (
		email       string
		phoneNumber string
	)
	id := uuid.New()
	code := verificationCode()
	err = VerifyPwd(input.Password, r.Config.PasswordConfig)
	if err != nil {
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrPasswordHash
		return
	}
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrCodeHash
		return
	}
	for i := 0; i < len(input.UserAttributes); i++ {
		switch {
		case input.UserAttributes[i].Name == EmailAttributeName:
			email = input.UserAttributes[i].Value
		case input.UserAttributes[i].Name == PhoneNumberAttributeName:
			phoneNumber = input.UserAttributes[i].Value
		default:
		}
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		_, err = r.EntClient.User.Query().Where(user.Email(email)).Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return
		}
		if err == nil {
			err = api.ErrUserExists
			return nil, err
		}
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(UserNameCaseSensitive(r.Config, input.Username)).
			SetPasswordHash(string(passwordHash)).
			SetEmail(email).
			SetPhoneNumber(phoneNumber).
			SetConfirmationCodeHash(string(codeHash)).
			SetUserAttributes(input.UserAttributes).
			SetActiveState(0).
			SetCodeTime(nowTime()).
			SetTokenState(0).
			Save(ctx)
		if err != nil {
			return
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, email, "邮箱验证码", code) != nil {
			err := api.ErrVerificationCode
			return nil, err
		}
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: EmailAttributeName, DeliveryMedium: "EMAIL", Destination: masker.Mobile(email)}, UserConfirmed: false, UserSub: id.String()}
		return
	}
	_, err = r.EntClient.User.Query().Where(user.Email(phoneNumber)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return
	}
	if err == nil {
		err = api.ErrUserExists
		return nil, err
	}
	_, err = r.EntClient.User.Create().
		SetID(id).
		SetUsername(UserNameCaseSensitive(r.Config, input.Username)).
		SetPasswordHash(string(passwordHash)).
		SetPhoneNumber(phoneNumber).
		SetEmail(email).
		SetConfirmationCodeHash(string(codeHash)).
		SetUserAttributes(input.UserAttributes).
		SetActiveState(0).
		SetCodeTime(nowTime()).
		SetTokenState(0).
		Save(ctx)
	if err != nil {
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, phoneNumber, code) != nil {
		err := api.ErrVerificationCode
		return nil, err
	}
	output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: PhoneNumberAttributeName, DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(phoneNumber)}, UserConfirmed: false, UserSub: id.String()}
	return
}

func (r *mutationResolver) ConfirmSignUp(ctx context.Context, input api.ConfirmSignUpInput) (output *api.ConfirmOutput, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	err = timeSub(u.CodeTime)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		err = api.ErrWrongVerificationCode
		return &api.ConfirmOutput{ConfirmStatus: false}, err
	}
	_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetActiveState(1).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}

func (r *mutationResolver) InitiateAuth(ctx context.Context, input api.InitiateAuthInput) (output *api.AuthenticationResult, err error) {
	if input.AuthFlow == "" {
		err = api.ErrAuthFlowIsNil
		return
	}
	if input.AuthFlow != "USER_PASSWORD_AUTH" && input.AuthFlow != "EMAIL_PASSWORD_AUTH" && input.AuthFlow != "PHONE_NUMBER_PASSWORD_AUTH" && input.AuthFlow != "REFRESH_TOKEN_AUTH" {
		err = api.ErrUnknownAuthFlow
		return

	}
	if input.AuthFlow == "USER_PASSWORD_AUTH" {
		if input.AuthParameters["Username"] == nil {
			err = api.ErrUsernameIsNil
			return
		}
		if input.AuthParameters["Password"] == nil {
			err = api.ErrPasswordIsNil
			return
		}
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.ActiveState == 0 {
			err = api.ErrUserNotActivated
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters["Password"].(string)))
		if err != nil {
			err = api.ErrWrongPassword
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "Cognito")
		refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
		return output, nil
	}
	if input.AuthFlow == "EMAIL_PASSWORD_AUTH" {
		if input.AuthParameters["Username"] == nil {
			err = api.ErrUsernameIsNil
			return
		}
		if input.AuthParameters["Password"] == nil {
			err = api.ErrPasswordIsNil
			return
		}
		u, err := r.EntClient.User.Query().Where(user.Email(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.ActiveState == 0 {
			err = api.ErrUserNotActivated
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters["Password"].(string)))
		if err != nil {
			err = api.ErrWrongPassword
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Email(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "Cognito")
		refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
		return output, nil
	}
	if input.AuthFlow == "PHONE_NUMBER_PASSWORD_AUTH" {
		if input.AuthParameters["Username"] == nil {
			err = api.ErrUsernameIsNil
			return
		}
		if input.AuthParameters["Password"] == nil {
			err = api.ErrPasswordIsNil
			return
		}
		u, err := r.EntClient.User.Query().Where(user.PhoneNumber(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.ActiveState == 0 {
			err = api.ErrUserNotActivated
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters["Password"].(string)))
		if err != nil {
			err = api.ErrWrongPassword
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.PhoneNumber(UserNameCaseSensitive(r.Config, input.AuthParameters["Username"].(string)))).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "Cognito")
		refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
		return output, nil
	}
	if input.AuthParameters["RefreshToken"] == nil {
		err = api.ErrRefreshTokenIsNil
		return
	}
	result, err := parseJwtToken(r.Config.JwtTokenConfig, input.AuthParameters["RefreshToken"].(string), "refresh")
	if err != nil {
		err = api.ErrParseJwtTokenFailed
		return
	}
	if result["Idp"].(string) == "Cognito" {
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, result["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.ActiveState == 0 {
			err = api.ErrUserNotActivated
			return nil, err
		}
		if u.TokenState == 0 {
			err = api.ErrTokenInvalid
			return nil, err
		}
		accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "Cognito")
		refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "Cognito")
		output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
		return output, nil
	}
	u, err := r.EntClient.SocialAccount.Query().Where(socialaccount.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	_, err = r.EntClient.SocialAccount.Update().Where(socialaccount.Username(result["Username"].(string))).SetTokenState(1).Save(ctx)
	if err != nil {
		return
	}
	accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "GitHub")
	idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "GitHub")
	refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "GitHub")
	if err != nil {
		return nil, err
	}
	output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
	return
}

func (r *queryResolver) GetUser(ctx context.Context, accessToken string) (output *api.GetUserResult, err error) {
	if accessToken == "" {
		err = api.ErrAccessTokenNil
		return
	}
	result, err := parseJwtToken(r.Config.JwtTokenConfig, accessToken, "access")
	if err != nil {
		err = api.ErrParseJwtTokenFailed
		return
	}
	if result["Idp"].(string) == "Cognito" {
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, result["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.TokenState == 0 {
			err = api.ErrTokenInvalid
			return nil, err
		}
		userAttributes := []*api.UserAttributes{{Name: "Email", Value: u.Email}, {Name: "PhoneNumber", Value: u.PhoneNumber}}
		output = &api.GetUserResult{Username: u.Username, UserAttributes: userAttributes}
		return output,nil
	}
	u, err := r.EntClient.SocialAccount.Query().Where(socialaccount.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return nil, err
	}
	if u.TokenState == 0 {
		err = api.ErrTokenInvalid
		return nil, err
	}
	identities, _ := json.Marshal(u.Identities)
	userAttributes := []*api.UserAttributes{{Name: "Email", Value: u.Email}, {Name: "identities", Value: string(identities)}}
	output = &api.GetUserResult{Username: u.Username, UserAttributes: userAttributes}
	return
}

func (r *mutationResolver) ChangePassword(ctx context.Context, input api.ChangePasswordInput) (output *api.ConfirmOutput, err error) {
	if input.AccessToken == "" {
		err = api.ErrAccessTokenNil
		return
	}
	result, err := parseJwtToken(r.Config.JwtTokenConfig, input.AccessToken, "access")
	if err != nil {
		err = api.ErrParseJwtTokenFailed
		return
	}
	if result["Idp"].(string) != "Cognito" {
		err = api.ErrAccountNotExist
		return
	}
	u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, result["Username"].(string)))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	if u.TokenState == 0 {
		err = api.ErrTokenInvalid
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.PreviousPassword))
	if err != nil {
		err = api.ErrWrongPassword
		return
	}
	if input.PreviousPassword == input.ProposedPassword {
		err = api.ErrSamePassword
		return
	}
	err = VerifyPwd(input.ProposedPassword, r.Config.PasswordConfig)
	if err != nil {
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.ProposedPassword), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrPasswordHash
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(result["Username"].(string))).SetPasswordHash(string(passwordHash)).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}

func (r *mutationResolver) ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) (output *api.CodeDeliveryDetails, err error) {
	code := verificationCode()
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrCodeHash
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, u.Email, "邮箱验证码", code) != nil {
			err = api.ErrVerificationCode
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetConfirmationCodeHash(string(codeHash)).SetCodeTime(nowTime()).Save(ctx)
		if err != nil {
			return nil, err
		}
		return &api.CodeDeliveryDetails{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: masker.Mobile(u.Email)}, nil
	}
	u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, u.PhoneNumber, code) != nil {
		err = api.ErrVerificationCode
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetConfirmationCodeHash(string(codeHash)).SetCodeTime(nowTime()).Save(ctx)
	if err != nil {
		return
	}
	output = &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(u.PhoneNumber)}
	return

}

func (r *mutationResolver) ResendConfirmationCode(ctx context.Context, input api.ResendConfirmationCodeInput) (output *api.ConfirmOutput, err error) {
	code := verificationCode()
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrCodeHash
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, u.Email, "邮箱验证码", code) != nil {
			err := api.ErrVerificationCode
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetConfirmationCodeHash(string(codeHash)).SetCodeTime(nowTime()).Save(ctx)
		if err != nil {
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		output = &api.ConfirmOutput{ConfirmStatus: true}
		return output, nil
	}
	u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, u.PhoneNumber, code) != nil {
		err = api.ErrVerificationCode
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetConfirmationCodeHash(string(codeHash)).SetCodeTime(nowTime()).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}

func (r *mutationResolver) ConfirmForgotPassword(ctx context.Context, input api.ConfirmForgotPasswordInput) (output *api.ConfirmOutput, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return
	}
	err = timeSub(u.CodeTime)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		err = api.ErrWrongVerificationCode
		return
	}
	err = VerifyPwd(input.Password, r.Config.PasswordConfig)
	if err != nil {
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		err = api.ErrPasswordHash
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, input.Username))).SetPasswordHash(string(passwordHash)).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}

func (r *mutationResolver) GlobalSignOut(ctx context.Context, input api.GlobalSignOutInput) (output *api.ConfirmOutput, err error) {
	if input.AccessToken == "" {
		err = api.ErrAccessTokenNil
		return
	}
	result, err := parseJwtToken(r.Config.JwtTokenConfig, input.AccessToken, "access")
	if err != nil {
		err = api.ErrParseJwtTokenFailed
		return
	}
	if result["Idp"].(string) == "Cognito" {
		u, err := r.EntClient.User.Query().Where(user.Username(UserNameCaseSensitive(r.Config, result["Username"].(string)))).Only(ctx)
		if err != nil {
			err = api.ErrAccountNotExist
			return nil, err
		}
		if u.TokenState == 0 {
			err = api.ErrTokenInvalid
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(UserNameCaseSensitive(r.Config, result["Username"].(string)))).SetTokenState(0).Save(ctx)
		if err != nil {
			return nil, err
		}
		output = &api.ConfirmOutput{ConfirmStatus: true}
		return output, nil
	}
	u, err := r.EntClient.SocialAccount.Query().Where(socialaccount.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		err = api.ErrAccountNotExist
		return nil, err
	}
	if u.TokenState == 0 {
		err = api.ErrTokenInvalid
		return nil, err
	}
	_, err = r.EntClient.SocialAccount.Update().Where(socialaccount.Username(result["Username"].(string))).SetTokenState(0).Save(ctx)
	if err != nil {
		return nil, err
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return output, nil
}

func (r *mutationResolver) InitiateOAuth(ctx context.Context, input api.InitiateOAuthInput) (output *api.AuthenticationResult, err error) {
	if input.IdpIdentifier != ("GitHub") {
		err = api.ErrUnknownIdpIdentifier
		return
	}
	token, err := getToken(input.Code)
	if err != nil {
		return
	}
	userInfo, err := getUserInfo(token["access_token"].(string))
	if err != nil {
		return
	}
	u, err := r.EntClient.SocialAccount.Query().Where(socialaccount.Username("GitHub_" + userInfo["login"].(string))).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return
	}
	if err == nil {
		_, err = r.EntClient.SocialAccount.Update().Where(socialaccount.Username("GitHub_" + userInfo["login"].(string))).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		accessToken, err := createAccessToken(r.Config.JwtTokenConfig, u.Username, "GitHub")
		idToken, err := createIdToken(r.Config.JwtTokenConfig, u.ID.String(), "GitHub")
		refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, u.Username, "GitHub")
		if err != nil {
			return nil, err
		}
		output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
		return output, nil
	}
	id := uuid.New()
	_, err = r.EntClient.SocialAccount.Create().
		SetID(id).
		SetUsername("GitHub_" + userInfo["login"].(string)).
		SetIdpIdentifier("GitHub").
		SetIdentities(userInfo).
		SetTokenState(1).
		Save(ctx)
	if err != nil {
		return
	}
	accessToken, err := createAccessToken(r.Config.JwtTokenConfig, "GitHub_"+userInfo["login"].(string), "GitHub")
	idToken, err := createIdToken(r.Config.JwtTokenConfig, id.String(), "GitHub")
	refreshToken, err := createRefreshToken(r.Config.JwtTokenConfig, "GitHub_"+userInfo["login"].(string), "GitHub")
	output = &api.AuthenticationResult{AccessToken: accessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: idToken, RefreshToken: refreshToken, TokenType: "Bearer"}
	return
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
