package api

import (
	"context"
)

type BootConfig struct {
	AllowSignInWithVerifiedEmailAddress bool
	AllowSignInWithVerifiedPhoneNumber  bool
	AllowSignInWithPreferredUsername    bool
	PreSignUpFunc                       func(ctx context.Context, input SignUpInput) error
	TimeSubFunc							func(input string) (err error)
	CreateCodeFunc						func() string
	CreateAccessTokenFunc				func(name string) (string, error)
	SendMailFunc                        func(stuEmail string, subject string, body string) (err error)
	SendMsgFunc                         func(tel string, code string) (err error)
}
type EmailConfig struct {
	User string
	Pass string
	Host string
	Port string
}

type PhoneConfig struct {
	AccesskeyId string
	AccessSecret string
	SignName string
	TemplateCode string
}