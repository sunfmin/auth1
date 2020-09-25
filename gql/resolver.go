package gql

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"context"
	"fmt"
	"math/rand"
	"time"
	"strconv"
	"gopkg.in/gomail.v2"
	 masker "github.com/ggwhite/go-masker"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/ent/user"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
)

type Resolver struct {
	EntClient *ent.Client
	Config    *api.BootConfig
}

func SendMail(mailTo []string, subject string, body string) error {
  
	mailConn := map[string]string{
		"user": "hd0728@qq.com", 
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
func DoSendMail(stuEmail , subject, body string) (e error) {
	mailTo := []string{stuEmail}
	err := SendMail(mailTo, subject, body)
	if err != nil {
		e = err
		return e
	}
	return nil
}
//阿里云的审核还没通过所以没测试
func SendMsg(tel string, code string) string {
	client, err := dysmsapi.NewClientWithAccessKey("cn-hangzhou", "<accesskeyId>", "<accessSecret>")
	request := dysmsapi.CreateSendSmsRequest()
	request.Scheme = "https"
	request.PhoneNumbers = tel //手机号变量值
	request.SignName = "" //签名
	request.TemplateCode = "" //模板编码
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
		DoSendMail(email,"邮箱验证码",code)
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
		SendMsg(phonenumber,code)
		output = &api.User{CodeDeliveryDetails: &api.CodeDeliveryDetails{AttributeName: "phone_number", DeliveryMedium: "PHONE_NUMBER", Destination: masker.Mobile(phonenumber)}, UserConfirmed: false, UserSub: id.String()}
		return

	}
	errs := fmt.Errorf("Config is nil")
	return nil, errs

}
func (r *mutationResolver) ConfirmSignUp(ctx context.Context, input api.ConfirmSignUpInput) (output *api.ConfirmUser, err error) {
	u, err := r.EntClient.User.Query().Where(user.Username(input.Username)).Only(ctx)
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.ConfirmationCodeHash), []byte(input.ConfirmationCode)) 
	if err != nil {
		output=&api.ConfirmUser{ConfirmUser:false}
		return output,nil
	}
	output=&api.ConfirmUser{ConfirmUser:true}
	return 
}
func (r *queryResolver) GetUser(ctx context.Context, accessToken string) ([]*api.User, error) {
	panic("not implemented")
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
