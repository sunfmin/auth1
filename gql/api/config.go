package api

import (
	"context"
)

type BootConfig struct {
	AllowSignInWithVerifiedEmailAddress bool
	AllowSignInWithVerifiedPhoneNumber  bool
	AllowSignInWithPreferredUsername    bool
	PreSignUpFunc                       func(ctx context.Context, input SignUpInput) error
	CreateAccessTokenFunc               func(jwtTokenConfig *JwtTokenConfig, name string) (string, error)
	SendMailFunc                        func(emailConfig *EmailConfig, email string, subject string, body string) (err error)
	SendMsgFunc                         func(phoneConfig *PhoneConfig, tel string, code string) (err error)
	EmailConfig                         *EmailConfig
	PhoneConfig                         *PhoneConfig
	JwtTokenConfig                      *JwtTokenConfig
	MinimumLength                       int
	RequireNumber                       bool
	RequireSpecialCharacter             bool
	RequireUppercaseLetters             bool
	RequireLowercaseLetters             bool
}

type EmailConfig struct {
	User string
	Pass string
	Host string
	Port string
}

type PhoneConfig struct {
	AccessKeyId  string
	AccessSecret string
	SignName     string
	TemplateCode string
}

type JwtTokenConfig struct {
	JwtSecretKey                string
	JwtExpireSecond             int
	RefreshTokenJwtSecretKey    string
	RefreshTokenJwtExpireSecond int
}