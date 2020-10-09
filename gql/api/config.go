package api

import (
	"context"
)

type BootConfig struct {
	AllowSignInWithVerifiedEmailAddress bool
	AllowSignInWithVerifiedPhoneNumber  bool
	AllowSignInWithPreferredUsername    bool
	PreSignUpFunc                       func(ctx context.Context, input SignUpInput) error
	SendMailFunc                        func(entconfig*EmailConfig,stuEmail string, subject string, body string) (err error)
	SendMsgFunc                         func(phoneconfig*PhoneConfig,tel string, code string) (err error)
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
type JwtTokenConfig struct {
	JwtSecretKey string
	JwtExpireSecond  int
	RefreshTokenJwtSecretKey string
	RefreshTokenJwtExpireSecond  int
}

