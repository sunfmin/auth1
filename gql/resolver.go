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
	EmailAttributeName       = "email"
	PhoneNumberAttributeName = "phone_number"
	timeLayout               = "2006-01-02 15:04:05"
)

func NewResolver(entClient *ent.Client, config *api.BootConfig) (r *Resolver) {

	if config.SendMailFunc == nil {
		config.SendMailFunc = SendMail
	}
	if config.SendMsgFunc == nil {
		config.SendMsgFunc = SendMsg
	}
	if config.CreateAccessTokenFunc == nil {
		config.CreateAccessTokenFunc = CreateAccessToken
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
	if config.AllowSignInWithVerifiedEmailAddress && config.AllowSignInWithVerifiedPhoneNumber {
		panic("verify email address and verify phone number can not be true the same time")
	}
	if !config.AllowSignInWithVerifiedEmailAddress && !config.AllowSignInWithVerifiedPhoneNumber {
		panic("verify email address and verify phone number can not be false the same time")
	}
	r = &Resolver{EntClient: entClient, Config: config}
	return
}
func NowTime() string {
	timeUnix := time.Now().Unix()
	formatTimeStr := time.Unix(timeUnix, 0).Format(timeLayout)
	return formatTimeStr
}
func TimeSub(input string) (err error) {
	local, _ := time.LoadLocation("Local")
	theTime, _ := time.ParseInLocation(timeLayout, input, local)
	TimeNow := time.Now()
	left := TimeNow.Sub(theTime)
	if left.Seconds() > 300 {
		err = fmt.Errorf("Captcha timeout")
		return
	}
	return
}
func VerificationCode() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	return code
}
func SendMail(EmailConfig *api.EmailConfig, stuEmail string, subject string, body string) (err error) {
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
func SendMsg(PhoneConfig *api.PhoneConfig, tel string, code string) (err error) {
	client, err := dysmsapi.NewClientWithAccessKey("cn-hangzhou", PhoneConfig.AccessKeyId, PhoneConfig.AccessSecret)
	request := dysmsapi.CreateSendSmsRequest()
	request.Scheme = "https"
	request.PhoneNumbers = tel                      //手机号变量值
	request.SignName = PhoneConfig.SignName         //签名
	request.TemplateCode = PhoneConfig.TemplateCode //模板编码
	request.TemplateParam = "{\"code\":\"" + code + "\"}"
	response, err := client.SendSms(request)
	fmt.Println(response.Code)
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
func CreateAccessToken(JwtTokenConfig *api.JwtTokenConfig, name string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.JwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.JwtSecretKey))
}
func CreateIdToken(JwtTokenConfig *api.JwtTokenConfig, id string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"ID":  id,
		"exp": time.Now().Add(time.Second * time.Duration(JwtTokenConfig.JwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.JwtSecretKey))
}
func CreateRefreshToken(JwtTokenConfig *api.JwtTokenConfig, id string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": id,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.RefreshTokenJwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.RefreshTokenJwtSecretKey))
}
func ParseJwtToken(JwtTokenConfig *api.JwtTokenConfig, s string) (jwt.MapClaims, error) {
	fn := func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtTokenConfig.JwtSecretKey), nil
	}
	result, error := jwt.Parse(s, fn)
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
	code := VerificationCode()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
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
		_, err = r.EntClient.User.Create().
			SetID(id).
			SetUsername(input.Username).
			SetPasswordHash(string(passwordHash)).
			SetEmail(email).
			SetPhoneNumber(phoneNumber).
			SetConfirmationCodeHash(string(codeHash)).
			SetUserAttributes(input.UserAttributes).
			SetActiveState(0).
			SetCodeTime(NowTime()).
			SetTokenState(0).
			Save(ctx)
		if err != nil {
			return
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, email, "邮箱验证码", code) != nil {
			err := fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: EmailAttributeName, DeliveryMedium: "EMAIL", Destination: masker.Mobile(email)}, UserConfirmed: false, UserSub: id.String()}
		return
	}
	_, err = r.EntClient.User.Create().
		SetID(id).
		SetUsername(input.Username).
		SetPasswordHash(string(passwordHash)).
		SetPhoneNumber(phoneNumber).
		SetEmail(email).
		SetConfirmationCodeHash(string(codeHash)).
		SetUserAttributes(input.UserAttributes).
		SetActiveState(0).
		SetCodeTime(NowTime()).
		SetTokenState(0).
		Save(ctx)
	if err != nil {
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, phoneNumber, code) != nil {
		err := fmt.Errorf("Verification code sending failed")
		return nil, err
	}
	output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: PhoneNumberAttributeName, DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(phoneNumber)}, UserConfirmed: false, UserSub: id.String()}
	return
}
func (r *mutationResolver) ConfirmSignUp(ctx context.Context, input api.ConfirmSignUpInput) (output *api.ConfirmOutput, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		err = fmt.Errorf("Account does not exist")
		return
	}
	err = TimeSub(u.CodeTime)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		err = fmt.Errorf("Wrong verification code")
		return &api.ConfirmOutput{ConfirmStatus: false}, err
	}
	_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetActiveState(1).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}
func (r *mutationResolver) InitiateAuth(ctx context.Context, input api.InitiateAuthInput) (output *api.AuthenticationResult, err error) {
	if input.AuthFlow == "" {
		err = fmt.Errorf("AuthFlow is nil")
		return
	}
	if input.AuthFlow != "USER_PASSWORD_AUTH" && input.AuthFlow != "EMAIL_PASSWORD_AUTH" && input.AuthFlow != "PHONENUMBER_PASSWORD_AUTH" {
		err = fmt.Errorf("Unknown AuthFlow")
		return

	}
	if input.AuthFlow == "USER_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Username(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			err = fmt.Errorf("Account does not exist")
			return nil, err
		}
		if u.ActiveState == 0 {
			err = fmt.Errorf("The user is not activated")
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			err = fmt.Errorf("Wrong password")
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.AuthParameters.Username)).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(r.Config.JwtTokenConfig, u.Username)
		Idtoken, err := CreateIdToken(r.Config.JwtTokenConfig, u.ID.String())
		RefreshToken, err := CreateRefreshToken(r.Config.JwtTokenConfig, u.Username)
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
		return output, nil
	}
	if input.AuthFlow == "EMAIL_PASSWORD_AUTH" {
		u, err := r.EntClient.User.Query().Where(user.Email(input.AuthParameters.Username)).Only(ctx)
		if err != nil {
			err = fmt.Errorf("Account does not exist")
			return nil, err
		}
		if u.ActiveState == 0 {
			err = fmt.Errorf("The user is not activated")
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
		if err != nil {
			err = fmt.Errorf("Wrong password")
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Email(input.AuthParameters.Username)).SetTokenState(1).Save(ctx)
		if err != nil {
			return nil, err
		}
		AccessToken, err := CreateAccessToken(r.Config.JwtTokenConfig, u.Username)
		Idtoken, err := CreateIdToken(r.Config.JwtTokenConfig, u.ID.String())
		RefreshToken, err := CreateRefreshToken(r.Config.JwtTokenConfig, u.Username)
		output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
		return output, nil
	}
	u, err := r.EntClient.User.Query().Where(user.PhoneNumber(input.AuthParameters.Username)).Only(ctx)
	if err != nil {
		err = fmt.Errorf("Account does not exist")
		return
	}
	if u.ActiveState == 0 {
		err = fmt.Errorf("The user is not activated")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.AuthParameters.Password))
	if err != nil {
		err = fmt.Errorf("Wrong password")
		return
	}
	_, err = r.EntClient.User.Update().Where(user.PhoneNumber(input.AuthParameters.Username)).SetTokenState(1).Save(ctx)
	if err != nil {
		return
	}
	AccessToken, err := CreateAccessToken(r.Config.JwtTokenConfig, u.Username)
	Idtoken, err := CreateIdToken(r.Config.JwtTokenConfig, u.ID.String())
	RefreshToken, err := CreateRefreshToken(r.Config.JwtTokenConfig, u.Username)
	output = &api.AuthenticationResult{AccessToken: AccessToken, ExpiresIn: r.Config.JwtTokenConfig.JwtExpireSecond, IDToken: Idtoken, RefreshToken: RefreshToken, TokenType: "Bearer"}
	return
}
func (r *queryResolver) GetUser(ctx context.Context, accessToken string) ([]*api.User, error) {
	panic("not implemented")
}
func (r *mutationResolver) ChangePassword(ctx context.Context, input api.ChangePasswordInput) (output *api.ConfirmOutput, err error) {
	if input.AccessToken == "" {
		err = fmt.Errorf("AccessToken is nil")
		return
	}
	result, err := ParseJwtToken(r.Config.JwtTokenConfig, input.AccessToken)
	if err != nil {
		err = fmt.Errorf("ParseJwtToken failed")
		return
	}
	u, err := r.EntClient.User.Query().Where(user.Username(result["Username"].(string))).Only(ctx)
	if err != nil {
		err = fmt.Errorf("Account does not exist")
		return
	}
	if u.TokenState == 0 {
		err = fmt.Errorf("Token is invalid")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(input.PreviousPassword))
	if err != nil {
		err = fmt.Errorf("Wrong PreviousPassword")
		return
	}
	if input.PreviousPassword == input.ProposedPassword {
		err = fmt.Errorf("The new password cannot be the same as the old password")
		return
	}
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.ProposedPassword), bcrypt.DefaultCost)
	_, err = r.EntClient.User.Update().Where(user.Username(result["Username"].(string))).SetPasswordHash(string(password_hash)).Save(ctx)
	if err != nil {
		err = fmt.Errorf("Update failed")
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}
func (r *mutationResolver) ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) (output *api.CodeDeliveryDetails, err error) {
	code := VerificationCode()
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			err = fmt.Errorf("Account does not exist")
			return nil, err
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, u.Email, "邮箱验证码", code) != nil {
			err = fmt.Errorf("Verification code sending failed")
			return nil, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).SetCodeTime(NowTime()).Save(ctx)
		if err != nil {
			return nil, err
		}
		return &api.CodeDeliveryDetails{AttributeName: "email", DeliveryMedium: "EMAIL", Destination: masker.Mobile(u.Email)}, nil
	}
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		err = fmt.Errorf("Account does not exist")
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, u.PhoneNumber, code) != nil {
		err = fmt.Errorf("Verification code sending failed")
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).SetCodeTime(NowTime()).Save(ctx)
	if err != nil {
		return
	}
	output = &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(u.PhoneNumber)}
	return

}
func (r *mutationResolver) ResendConfirmationCode(ctx context.Context, input api.ResendConfirmationCodeInput) (output *api.ConfirmOutput, err error) {
	code := VerificationCode()
	code_hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if r.Config.AllowSignInWithVerifiedEmailAddress {
		u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
		if err != nil {
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		if r.Config.SendMailFunc(r.Config.EmailConfig, u.Email, "邮箱验证码", code) != nil {
			err := fmt.Errorf("Verification code sending failed")
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).SetCodeTime(NowTime()).Save(ctx)
		if err != nil {
			return &api.ConfirmOutput{ConfirmStatus: false}, err
		}
		output = &api.ConfirmOutput{ConfirmStatus: true}
		return output, nil
	}
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		return
	}
	if r.Config.SendMsgFunc(r.Config.PhoneConfig, u.PhoneNumber, code) != nil {
		err = fmt.Errorf("Verification code sending failed")
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetConfirmationCodeHash(string(code_hash)).SetCodeTime(NowTime()).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return

}
func (r *mutationResolver) ConfirmForgotPassword(ctx context.Context, input api.ConfirmForgotPasswordInput) (output *api.ConfirmOutput, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		err = fmt.Errorf("Account does not exist")
		return
	}
	err = TimeSub(u.CodeTime)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode))
	if err != nil {
		err = fmt.Errorf("Wrong verification code")
		return
	}
	password_hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	_, err = r.EntClient.User.Update().Where(user.Username(input.Username)).SetPasswordHash(string(password_hash)).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}
func (r *mutationResolver) GlobalSignOut(ctx context.Context, input api.GlobalSignOutInput) (output *api.ConfirmOutput, err error) {
	if input.AccessToken == "" {
		err = fmt.Errorf("AccessToken is nil")
		return
	}
	result, err := ParseJwtToken(r.Config.JwtTokenConfig, input.AccessToken)
	if err != nil {
		return
	}
	_, err = r.EntClient.User.Update().Where(user.Username(result["Username"].(string))).SetTokenState(0).Save(ctx)
	if err != nil {
		return
	}
	output = &api.ConfirmOutput{ConfirmStatus: true}
	return
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
