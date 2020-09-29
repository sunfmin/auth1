package api

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
	"gopkg.in/gomail.v2"
)

type BootConfig struct {
	AllowSignInWithVerifiedEmailAddress bool
	AllowSignInWithVerifiedPhoneNumber  bool
	AllowSignInWithPreferredUsername    bool
	PreSignUpFunc                       func(ctx context.Context, input SignUpInput) error
}
type EmailConfig struct {
	user string
	pass string
	host string
	port string
}

func (Config BootConfig) SendMailFunc(stuEmail string, subject string, body string) (err error) {
	var e *EmailConfig = &EmailConfig{user: "******@qq.com", pass: "授权码", host: "smtp.qq.com", port: "465"}
	mailTo := []string{stuEmail}
	port, _ := strconv.Atoi(e.port)

	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(e.user, "验证码"))
	m.SetHeader("To", mailTo...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(e.host, port, e.user, e.pass)
	err = d.DialAndSend(m)
	if err != nil {
		return
	}
	return
}
func (Config BootConfig) SendMsgFunc(tel string, code string) (err error) {
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
		err = fmt.Errorf("frequency_limit")
		return
	}
	if err != nil {
		err = fmt.Errorf("failed")
		return
	}
	return
}
