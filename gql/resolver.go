package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"github.com/dgrijalva/jwt-go"
	masker "github.com/ggwhite/go-masker"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/ent/user"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

type Resolver struct {
	EntClient *ent.Client
	Config    *api.BootConfig
}

const (
	JwtSecretKey    = "welcomelogin"
	JwtExpireSecond = 3600
)

func CreateAccessToken(name string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * JwtExpireSecond).Unix(),
	})

	return token.SignedString([]byte(JwtSecretKey))
}
func CreateIdToken(id string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"ID":  id,
		"exp": time.Now().Add(time.Second * JwtExpireSecond).Unix(),
	})

	return token.SignedString([]byte(JwtSecretKey))
}
func ParseJwtToken(s string) (jwt.MapClaims, error) {
	fn := func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtSecretKey), nil
	}
	result, error := jwt.Parse(s, fn)
	if error != nil {
		return nil, error
	}
	finToken := result.Claims.(jwt.MapClaims)
	return finToken, nil
}
func SendMail(mailTo []string, subject string, body string) error {

	mailConn := map[string]string{
		"user": "hd07**@qq.com",
		"pass": "填授权码",
		"host": "smtp.qq.com",
		"port": "465",
	}
	port, _ := strconv.Atoi(mailConn["port"])

	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(mailConn["user"], "验证码"))
	m.SetHeader("To", mailTo...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(mailConn["host"], port, mailConn["user"], mailConn["pass"])
	err := d.DialAndSend(m)
	return err
}
func DoSendMail(stuEmail, subject, body string) (e error) {
	mailTo := []string{stuEmail}
	err := SendMail(mailTo, subject, body)
	if err != nil {
		e = err
		return e
	}
	return nil
}
func SendMsg(tel string, code string) string {
	client, err := dysmsapi.NewClientWithAccessKey("cn-hangzhou", "<accesskeyId>", "<accessSecret>")
	request := dysmsapi.CreateSendSmsRequest()
	request.Scheme = "https"
	request.PhoneNumbers = tel //手机号变量值
	request.SignName = ""      //签名
	request.TemplateCode = ""  //模板编码
	request.TemplateParam = "{\"code\":\"" + code + "\"}"
	response, err := client.SendSms(request)
	fmt.Println(response.Code)
	if response.Code == "isv.BUSINESS_LIMIT_CONTROL" {
		return "frequency_limit"
	}
	if err != nil {
		fmt.Print(err.Error())
		return "failed"
	}
	return "success"
}
func (r *mutationResolver) SignUp(ctx context.Context, input api.SignUpInput) (output *api.User, err error) {
	if r.Config.AllowSignInWithVerifiedEmailAddress && r.Config.AllowSignInWithVerifiedPhoneNumber {
		errs := fmt.Errorf("Config is all true")
		return nil, errs
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress == false && r.Config.AllowSignInWithVerifiedPhoneNumber == false {
		errs := fmt.Errorf("Config is all false")
		return nil, errs
	}
	var (
		email       string
		phonenumber string
	)
	id := uuid.New()
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	for i := 0; i < len(input.UserAttributes); i++ {
		switch {
		case input.UserAttributes[i].Name == "email":
			email = input.UserAttributes[i].Value
		case input.UserAttributes[i].Name == "phone_number":
			phonenumber = input.UserAttributes[i].Value
		default:
		}
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(input.Username).
			SetPasswordHash(string(password_hash)).
			SetEmail(email).
			SetPhoneNumber(phonenumber).
			SetConfirmationCodeHash(string(code_hash)).
			SetUserAttributes(input.UserAttributes).
			Save(ctx)
		if err != nil {
			return
		}
		if DoSendMail(email, "邮箱验证码", code) != nil {
			errs := fmt.Errorf("Verification code sending failed")
			return nil, errs
		}
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: masker.Mobile(email)}, UserConfirmed: false, UserSub: id.String()}
		return
	}
	if r.Config.AllowSignInWithVerifiedPhoneNumber {
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(input.Username).
			SetPasswordHash(string(password_hash)).
			SetPhoneNumber(phonenumber).
			SetEmail(email).
			SetConfirmationCodeHash(string(code_hash)).
			SetUserAttributes(input.UserAttributes).
			Save(ctx)
		if err != nil {
			return
		}
		SendMsg(phonenumber, code)
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(phonenumber)}, UserConfirmed: false, UserSub: id.String()}
		return

	}
	errs := fmt.Errorf("Config is nil")
	return nil, errs

}
func (r *queryResolver) ConfirmSignUp(ctx context.Context, input api.ConfirmSignUpInput) (output bool, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		output = false
		return output, nil
	}
	output = true
	return
}
func (r *queryResolver) InitiateAuth(ctx context.Context, input api.InitiateAuthInput) (output *api.AuthenticationResult, err error) {
	if input.AuthFlow == "" {
		errs := fmt.Errorf("AuthFlow is nil")
		return nil, errs
	}
	if input.AuthFlow != "USER_PASSWORD_AUTH" && input.AuthFlow != "EMAIL_PASSWORD_AUTH" && input.AuthFlow != "PHONENUMBER_PASSWORD_AUTH" {
		errs := fmt.Errorf("Unknow AuthFlow")
		return nil, errs

	}
	if input.AuthFlow == "USER_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Username(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(input.AuthParameters.Username)
		Idtoken, err := CreateIdToken(u.ID.String())
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: "", TokenType: ""}
		return output, nil
	}
	if input.AuthFlow == "EMAIL_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Email(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(input.AuthParameters.Username)
		Idtoken, err := CreateIdToken(u.ID.String())
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: "", TokenType: ""}
		return output, nil
	}
	u, err := r.EntClient.User.Query().Where(user.PhoneNumber(input.AuthParameters.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
	if err != nil {
		return
	}
	AccessToken, err := CreateAccessToken(input.AuthParameters.Username)
	Idtoken, err := CreateIdToken(u.ID.String())
	output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: JwtExpireSecond, IDToken: Idtoken, RefreshToken: "", TokenType: ""}
	return
}
func (r *queryResolver) GetUser(ctx context.Context, accessToken string) ([]*api.User, error) {
	panic("not implemented")
}
func (r *mutationResolver) ChangePassword(ctx context.Context, input api.ChangePasswordInput) (output bool, err error) {
	if input.AccessToken == "" {
		err := fmt.Errorf("AccessToken is nil")
		return false, err
	}
	result, err := ParseJwtToken(input.AccessToken)
	if err != nil {
		return
	}
	u, err := r.EntClient.User.Query().Where(user.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.PreviousPassword))
	if err != nil {
		return
	}
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.ProposedPassword), bcrypt.DefaultCost)
	_, err = r.EntClient.User.Update().Where(user.Username(result["Username"].(string))).SetPasswordHash(string(password_hash)).Save(ctx)
	if err != nil {
		return
	}
	return true, nil
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
