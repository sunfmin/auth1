package api

import "fmt"

var (
	ErrVerificationCode = fmt.Errorf("verification code sending failed")
	ErrAccountNotExist = fmt.Errorf("Account does not exist")
	ErrWrongverificationcode = fmt.Errorf("Wrong verification code") 
	ErrAuthFlowIsNil = fmt.Errorf("AuthFlow is nil") 
	ErrUnknownAuthFlow = fmt.Errorf("Unknown AuthFlow")
	ErrUserNotActivated = fmt.Errorf("User is not activated") 
	ErrWrongPassword = fmt.Errorf("Wrong password") 
	ErrAccessTokenNil = fmt.Errorf("AccessToken is nil") 
	ErrParseJwtTokenFailed = fmt.Errorf("ParseJwtToken failed")
	ErrTokeInvalid = fmt.Errorf("Toke is invalid")
	ErrSamePassword = fmt.Errorf("The new password cannot be the same as the old password")
	ErrCaptchaTimeout = fmt.Errorf("Captcha timeout")
	ErrPasswordHash = fmt.Errorf("Passwordhash creation failed")
	ErrCodeHash = fmt.Errorf("Codehash creation failed")
	ErrUserExists = fmt.Errorf("User already exists")
	ErrPasswordNumber = fmt.Errorf("The password need number")
	ErrPasswordEmpty = fmt.Errorf("The password is empty")
	ErrPasswordTooShort = fmt.Errorf("The password is too short")
	ErrPasswordSpecialCharacter = fmt.Errorf("The password need special character")
	ErrPasswordUppercaseLetters = fmt.Errorf("The password need special uppercase letters")
	ErrPasswordLowercaseLetters = fmt.Errorf("The password need special lowercase letters")
)
