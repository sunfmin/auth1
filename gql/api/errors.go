package api

import "fmt"

var (
	ErrVerificationCode         = fmt.Errorf("verification code sending failed")
	ErrAccountNotExist          = fmt.Errorf("account does not exist")
	ErrWrongVerificationCode    = fmt.Errorf("wrong verification code")
	ErrAuthFlowIsNil            = fmt.Errorf("auth flow is nil")
	ErrUnknownAuthFlow          = fmt.Errorf("unknown auth flow")
	ErrUserNotActivated         = fmt.Errorf("user is not activated")
	ErrWrongPassword            = fmt.Errorf("wrong password")
	ErrAccessTokenNil           = fmt.Errorf("access token is nil")
	ErrParseJwtTokenFailed      = fmt.Errorf("parse jwt token failed")
	ErrTokenInvalid             = fmt.Errorf("token is invalid")
	ErrSamePassword             = fmt.Errorf("the new password cannot be the same as the old password")
	ErrCaptchaTimeout           = fmt.Errorf("captcha timeout")
	ErrPasswordHash             = fmt.Errorf("passwordhash creation failed")
	ErrCodeHash                 = fmt.Errorf("code hash creation failed")
	ErrUserExists               = fmt.Errorf("user already exists")
	ErrPasswordNumber           = fmt.Errorf("the password need to contain number")
	ErrPasswordEmpty            = fmt.Errorf("the password is empty")
	ErrPasswordTooShort         = fmt.Errorf("the password is too short")
	ErrPasswordSpecialCharacter = fmt.Errorf("the password need special character")
	ErrPasswordUppercaseLetters = fmt.Errorf("the password need uppercase letters")
	ErrPasswordLowercaseLetters = fmt.Errorf("the password need lowercase letters")
)
