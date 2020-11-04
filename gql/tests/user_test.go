package tests

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/ent"
	"github.com/sunfmin/auth1/gql/api"
	"golang.org/x/crypto/bcrypt"
)

func sendMailTest(EmailConfig *api.EmailConfig, stuEmail string, subject string, body string) (err error) {
	if stuEmail == "test_error" {
		err := api.ErrVerificationCode
		return err
	}
	fmt.Printf("send success")
	return nil
}
func sendMsgTest(PhoneConfig *api.PhoneConfig, tel string, code string) (err error) {
	if tel == "test_error" {
		err := api.ErrVerificationCode
		return err
	}
	fmt.Print("send success")
	return nil
}

func createAccessToken(JwtTokenConfig *api.JwtTokenConfig, name string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.JwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.JwtSecretKey))
}
func createRefreshToken(JwtTokenConfig *api.JwtTokenConfig, name string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username": name,
		"exp":      time.Now().Add(time.Second * time.Duration(JwtTokenConfig.RefreshTokenJwtExpireSecond)).Unix(),
	})

	return token.SignedString([]byte(JwtTokenConfig.RefreshTokenJwtSecretKey))
}

func NowTime() string {
	timeUnix := time.Now().Unix()
	formatTimeStr := time.Unix(timeUnix, 0).Format("2006-01-02 15:04:05")
	return formatTimeStr
}

var testAccessToken, _ = createAccessToken(&api.JwtTokenConfig{JwtSecretKey: "welcomelogin", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "refreshtoken", RefreshTokenJwtExpireSecond: 2592000}, "test")
var failedAccessToken, _ = createAccessToken(&api.JwtTokenConfig{JwtSecretKey: "failed", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "fail", RefreshTokenJwtExpireSecond: 2592000}, "test")
var testRefreshToken, _ = createRefreshToken(&api.JwtTokenConfig{JwtSecretKey: "welcomelogin", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "refreshtoken", RefreshTokenJwtExpireSecond: 2592000}, "test")
var failedRefreshToken, _ = createRefreshToken(&api.JwtTokenConfig{JwtSecretKey: "failed", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "fail", RefreshTokenJwtExpireSecond: 2592000}, "test")
var codeHash, _ = bcrypt.GenerateFromPassword([]byte("111111"), bcrypt.DefaultCost)
var passwordHash, _ = bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

var TestCfg = &api.BootConfig{
	AllowSignInWithVerifiedEmailAddress: true,
	AllowSignInWithVerifiedPhoneNumber:  false,
	AllowSignInWithPreferredUsername:    false,
	UsernameCaseSensitive:               false,
	SendMailFunc:                        sendMailTest,
	SendMsgFunc:                         sendMsgTest,
	EmailConfig:                         &api.EmailConfig{User: "", Pass: "", Host: "smtp.qq.com", Port: "465"},
	PhoneConfig:                         &api.PhoneConfig{AccessKeyId: "<accesskeyId>", AccessSecret: "<accessSecret>", SignName: "签名", TemplateCode: "模板编码"},
	JwtTokenConfig:                      &api.JwtTokenConfig{JwtSecretKey: "welcomelogin", JwtExpireSecond: 3600, RefreshTokenJwtSecretKey: "refreshtoken", RefreshTokenJwtExpireSecond: 2592000},
	PasswordConfig:                      &api.PasswordConfig{MinimumLength: 8, RequireNumber: true, RequireSpecialCharacter: true, RequireUppercaseLetters: true, RequireLowercaseLetters: true},
}

var userMutationCases = []GraphqlCase{
	{
		name:       "SignUp normal",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "Test@12345678",
				},
			},
		},
		expected: &api.Data{
			SignUp: &api.User{
				CodeDeliveryDetails: &api.CodeDeliveryDetails{
					AttributeName:  "",
					DeliveryMedium: "",
					Destination:    "",
				},
			},
		},
	}, {
		name:       "SignUp password requires numbers",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "Test@abcdefg",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordNumber.Error(),
	}, {
		name:       "SignUp password empty",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordEmpty.Error(),
	}, {
		name:       "SignUp password is too short",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "1",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordTooShort.Error(),
	}, {
		name:       "SignUp password need special character",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "Test12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordSpecialCharacter.Error(),
	}, {
		name:       "SignUp password need uppercase letters",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordUppercaseLetters.Error(),
	}, {
		name:       "SignUp password need lowercase letters",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test@test.com",
						},
						{
							Name:  "phone_number",
							Value: "test",
						},
					},
					Password: "TEST@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordLowercaseLetters.Error(),
	}, {
		name:       "SignUp verification code sending failed",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test_error",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test_error",
						},
						{
							Name:  "phone_number",
							Value: "test_error",
						},
					},
					Password: "Test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrVerificationCode.Error(),
	}, {
		name: "SignUp user already exists",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
			mutation ($input: SignUpInput!) {
				SignUp(input: $input) {
					CodeDeliveryDetails{
						AttributeName,
						DeliveryMedium,
						Destination
					  },
				   UserConfirmed,
	                  UserSub
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.SignUpInput{
					Username: "test_error",
					UserAttributes: []*api.AttributeType{
						{
							Name:  "email",
							Value: "test_error",
						},
						{
							Name:  "phone_number",
							Value: "test_error",
						},
					},
					Password: "Test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrUserExists.Error(),
	}, {
		name: "ConfirmSignUp normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
			mutation ConfirmSignUp($input:ConfirmSignUpInput!){
			  ConfirmSignUp(input:$input){
						ConfirmStatus,
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username:         "test",
					ConfirmationCode: "111111",
				},
			},
		},
		expected: &api.Data{
			ConfirmSignUp: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	}, {
		name:       "ConfirmSignUp account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
			mutation ConfirmSignUp($input:ConfirmSignUpInput!){
			  ConfirmSignUp(input:$input){
						ConfirmStatus,
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username:         "test",
					ConfirmationCode: "111111",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "ConfirmSignUp verification code error",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetID(uuid.New()).
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
			mutation ConfirmSignUp($input:ConfirmSignUpInput!){
			  ConfirmSignUp(input:$input){
						ConfirmStatus,
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username:         "test_error",
					ConfirmationCode: "000000",
				},
			},
		},
		expectedError: "graphql: " + api.ErrWrongVerificationCode.Error(),
	}, {
		name: "ConfirmSignUp verification code timeout",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetCodeTime("2006-01-02 15:04:05").
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
			mutation ConfirmSignUp($input:ConfirmSignUpInput!){
			  ConfirmSignUp(input:$input){
						ConfirmStatus,
				}
			}
			`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmSignUpInput{
					Username:         "test_error",
					ConfirmationCode: "111111",
				},
			},
		},
		expectedError: "graphql: " + api.ErrCaptchaTimeout.Error(),
	}, {
		name: "ChangePassword normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "Test@12345678",
				},
			},
		},
		expected: &api.Data{
			ChangePassword: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	}, {
		name: "ChangePassword parsejwttoken failed",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      failedAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "Test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrParseJwtTokenFailed.Error(),
	}, {
		name: "ChangePassword password is too short",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "Test@12",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordTooShort.Error(),
	}, {
		name: "ChangePassword password is empty",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordEmpty.Error(),
	}, {
		name: "ChangePassword password need special character",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "Test1235678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordSpecialCharacter.Error(),
	}, {
		name: "ChangePassword password need number",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "Test@qwweerrrtt",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordNumber.Error(),
	}, {
		name: "ChangePassword password need uppercase letters",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordUppercaseLetters.Error(),
	}, {
		name: "ChangePassword password need lowercase letters",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "TEST@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordLowercaseLetters.Error(),
	}, {
		name: "ChangePassword token is invalid",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "new_password",
				},
			},
		},
		expectedError: "graphql: " + api.ErrTokenInvalid.Error(),
	}, {
		name:       "ChangePassword accesstoken is nil",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      "",
					PreviousPassword: "password",
					ProposedPassword: "new_password",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccessTokenNil.Error(),
	}, {
		name:       "ChangePassword account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "new_password",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "ChangePassword wrong previouspassword",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetTokenState(1).
				SetPasswordHash(string(passwordHash)).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "wrong_password",
					ProposedPassword: "new_password",
				},
			},
		},
		expectedError: "graphql: " + api.ErrWrongPassword.Error(),
	}, {
		name: "ChangePassword password no change",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetTokenState(1).
				SetPasswordHash(string(passwordHash)).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ChangePassword($input:ChangePasswordInput!){
		  ChangePassword(input:$input){
			ConfirmStatus,
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ChangePasswordInput{
					AccessToken:      testAccessToken,
					PreviousPassword: "password",
					ProposedPassword: "password",
				},
			},
		},
		expectedError: "graphql: " + api.ErrSamePassword.Error(),
	}, {
		name: "ForgotPassword normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ForgotPasswordInput!){
		  ForgotPassword(input:$input){
			AttributeName,
			DeliveryMedium,
			Destination
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ForgotPasswordInput{
					Username: "test",
				},
			},
		},
		expected: &api.Data{
			ForgotPassword: &api.CodeDeliveryDetails{},
		},
	}, {
		name:       "ForgotPassword account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ($input:ForgotPasswordInput!){
		  ForgotPassword(input:$input){
			AttributeName,
			DeliveryMedium,
			Destination
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ForgotPasswordInput{
					Username: "test_err",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "ForgotPassword verification code sending failed",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ForgotPasswordInput!){
		  ForgotPassword(input:$input){
			AttributeName,
			DeliveryMedium,
			Destination
		  }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ForgotPasswordInput{
					Username: "test_error",
				},
			},
		},
		expectedError: "graphql: " + api.ErrVerificationCode.Error(),
	}, {
		name: "ConfirmForgotPassword normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
		  ConfirmForgotPassword(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "Test@12345678",
				},
			},
		},
		expected: &api.Data{
			ConfirmForgotPassword: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	}, {
		name: "ConfirmForgotPassword password is too short",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "Test@12",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordTooShort.Error(),
	}, {
		name: "ConfirmForgotPassword password is empty",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordEmpty.Error(),
	}, {
		name: "ConfirmForgotPassword password need special character",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "Test1235678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordSpecialCharacter.Error(),
	}, {
		name: "ConfirmForgotPassword password need number",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "Test@qwweerrrtt",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordNumber.Error(),
	}, {
		name: "ConfirmForgotPassword password need uppercase letters",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordUppercaseLetters.Error(),
	}, {
		name: "ConfirmForgotPassword password need lowercase letters",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
			ConfirmForgotPassword(input:$input){
				  ConfirmStatus,
			  }
		  }
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "TEST@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordLowercaseLetters.Error(),
	}, {
		name:       "ConfirmForgotPassword account does not exist",
		bootConfig: TestCfg,
		fixture:    nil,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
		  ConfirmForgotPassword(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test",
					ConfirmationCode: "111111",
					Password:         "Test@12345678",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "ConfirmForgotPassword verification code error",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetConfirmationCodeHash(string(codeHash)).
				SetCodeTime(NowTime()).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
		  ConfirmForgotPassword(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test_error",
					ConfirmationCode: "000000",
					Password:         "test_error",
				},
			},
		},
		expectedError: "graphql: " + api.ErrWrongVerificationCode.Error(),
	}, {
		name: "ConfirmForgotPassword verification code timeout",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetConfirmationCodeHash(string(codeHash)).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ConfirmForgotPasswordInput!){
		  ConfirmForgotPassword(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ConfirmForgotPasswordInput{
					Username:         "test_error",
					ConfirmationCode: "111111",
					Password:         "test_error",
				},
			},
		},
		expectedError: "graphql: " + api.ErrCaptchaTimeout.Error(),
	}, {
		name: "ResendConfirmationCode normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ResendConfirmationCodeInput!){
		  ResendConfirmationCode(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ResendConfirmationCodeInput{
					Username: "test",
				},
			},
		},
		expected: &api.Data{
			ResendConfirmationCode: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	}, {
		name: "ResendConfirmationCode verification code sending failed",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:ResendConfirmationCodeInput!){
		  ResendConfirmationCode(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ResendConfirmationCodeInput{
					Username: "test_error",
				},
			},
		},
		expectedError: "graphql: " + api.ErrVerificationCode.Error(),
	}, {
		name:       "ResendConfirmationCode account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ($input:ResendConfirmationCodeInput!){
		  ResendConfirmationCode(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.ResendConfirmationCodeInput{
					Username: "test_error",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "InitiateAuth USER_PASSWORD_AUTH normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SetPasswordHash(string(passwordHash)).
				SetActiveState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Username": "test",
						"Password": "password",
					},
				},
			},
		},
		expected: &api.Data{
			InitiateAuth: &api.AuthenticationResult{
				ExpiresIn: 3600,
			},
		},
	}, {
		name: "InitiateAuth REFRESH_TOKEN_AUTH normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetActiveState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "REFRESH_TOKEN_AUTH",
					AuthParameters: map[string]interface{}{
						"RefreshToken": testRefreshToken,
					},
				},
			},
		},
		expected: &api.Data{
			InitiateAuth: &api.AuthenticationResult{
				ExpiresIn: 3600,
			},
		},
	}, {
		name: "InitiateAuth username is nil",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SetPasswordHash(string(passwordHash)).
				SetActiveState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Password": "password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrUsernameIsNil.Error(),
	}, {
		name: "InitiateAuth password is nil",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SetPasswordHash(string(passwordHash)).
				SetActiveState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Username": "test",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrPasswordIsNil.Error(),
	}, {
		name: "InitiateAuth refreshtoken is nil",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetActiveState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow:       "REFRESH_TOKEN_AUTH",
					AuthParameters: map[string]interface{}{},
				},
			},
		},
		expectedError: "graphql: " + api.ErrRefreshTokenIsNil.Error(),
	}, {
		name: "InitiateAuth parsejwttoken failed",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetPasswordHash(string(passwordHash)).
				SetTokenState(1).
				SetActiveState(1).
				SetID(uuid.New()).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "REFRESH_TOKEN_AUTH",
					AuthParameters: map[string]interface{}{
						"RefreshToken": "failed",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrParseJwtTokenFailed.Error(),
	}, {
		name: "InitiateAuth user is not activated",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetID(uuid.New()).
				SetActiveState(0).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Username": "test_error",
						"Password": "password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrUserNotActivated.Error(),
	}, {
		name:       "InitiateAuth AuthFlow is nil",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "",
					AuthParameters: map[string]interface{}{
						"Username": "test_error",
						"Password": "password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrAuthFlowIsNil.Error(),
	}, {
		name:       "InitiateAuth Unknown AuthFlow",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "Unknown_AuthFlow",
					AuthParameters: map[string]interface{}{
						"Username": "test_error",
						"Password": "password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrUnknownAuthFlow.Error(),
	}, {
		name:       "InitiateAuth account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Username": "test_error",
						"Password": "password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	}, {
		name: "InitiateAuth Wrong Password",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test_error").
				SetPhoneNumber("test_error").
				SetEmail("test_error").
				SetID(uuid.New()).
				SetPasswordHash(string(passwordHash)).
				SetActiveState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation InitiateAuth($input:InitiateAuthInput!){
		  InitiateAuth(input:$input){
			AccessToken,
			ExpiresIn,
			IdToken,
			RefreshToken,
			TokenType
          }
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.InitiateAuthInput{
					AuthFlow: "USER_PASSWORD_AUTH",
					AuthParameters: map[string]interface{}{
						"Username": "test_error",
						"Password": "wrong_password",
					},
				},
			},
		},
		expectedError: "graphql: " + api.ErrWrongPassword.Error(),
	}, {
		name: "GlobalSignOut normal",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SetTokenState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:GlobalSignOutInput!){
		  GlobalSignOut(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.GlobalSignOutInput{
					AccessToken: testAccessToken,
				},
			},
		},
		expected: &api.Data{
			GlobalSignOut: &api.ConfirmOutput{
				ConfirmStatus: true,
			},
		},
	}, {
		name: "GlobalSignOut parsejwttoken failed",
		fixture: func(ctx context.Context, client *ent.Client) {
			client.User.Create().
				SetUsername("test").
				SetPhoneNumber("test").
				SetEmail("test").
				SetID(uuid.New()).
				SetTokenState(1).
				SaveX(ctx)
		},
		bootConfig: TestCfg,
		query: `
		mutation ($input:GlobalSignOutInput!){
		  GlobalSignOut(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.GlobalSignOutInput{
					AccessToken: failedAccessToken,
				},
			},
		},
		expectedError: "graphql: " + api.ErrParseJwtTokenFailed.Error(),
	}, {
		name:       "GlobalSignOut accessToken is nil",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ($input:GlobalSignOutInput!){
		  GlobalSignOut(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.GlobalSignOutInput{
					AccessToken: "",
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccessTokenNil.Error(),
	}, {
		name:       "GlobalSignOut account does not exist",
		fixture:    nil,
		bootConfig: TestCfg,
		query: `
		mutation ($input:GlobalSignOutInput!){
		  GlobalSignOut(input:$input){
				ConfirmStatus,
			}
		}
		`,
		vars: []Var{
			{
				name: "input",
				val: api.GlobalSignOutInput{
					AccessToken: testAccessToken,
				},
			},
		},
		expectedError: "graphql: " + api.ErrAccountNotExist.Error(),
	},
}
