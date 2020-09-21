package aws_cognito_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pascaldekloe/jwt"
)

var sess = session.Must(session.NewSession(aws.NewConfig().
	WithMaxRetries(3),
))

var p1 = cip.New(sess, aws.NewConfig().WithRegion("us-east-1"))

var clientId = aws.String("2knvrtld8j6cosq7e477rhdu5j")

var poolId = aws.String("us-east-1_B1sFvc4jI")

var password = aws.String("12345678abcA@")
var username = aws.String("felix")

func TestSignUp(t *testing.T) {

	tryDeleteUser("felix")
	output, err := p1.SignUp(&cip.SignUpInput{
		ClientId: clientId,
		Username: username,
		UserAttributes: []*cip.AttributeType{
			//{
			//	Name:  aws.String("phone_number"),
			//	Value: aws.String("+8618072965771"),
			//},
			{
				Name:  aws.String("email"),
				Value: aws.String("sunfmin@gmail.com"),
			},
		},
		Password: password,
	})
	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}
	/*

		{
		  CodeDeliveryDetails: {
		    AttributeName: "email",
		    DeliveryMedium: "EMAIL",
		    Destination: "s***@g***.com"
		  },
		  UserConfirmed: false,
		  UserSub: "bd2a070b-b8db-4a6a-95a2-29b290f0709e"
		}
	*/
}

func tryDeleteUser(username string) {
	_, err := p1.AdminDeleteUser(&cip.AdminDeleteUserInput{
		UserPoolId: poolId,
		Username:   aws.String(username),
	})

	if err != nil {
		fmt.Println(err)
	}
}

func TestConfirmUser(t *testing.T) {

	output, err := p1.ConfirmSignUp(&cip.ConfirmSignUpInput{
		ClientId:         clientId,
		Username:         username,
		ConfirmationCode: aws.String("702420"),
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}
	/*
		{

		}
	*/
}

func TestChangePassword(t *testing.T) {
	accessToken := "eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJldmVudF9pZCI6Ijg1ZGMzMjE3LTM5NDMtNDZkZS05NDE4LTUyYWZkNWZkZjY4NyIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDA2NzMyMjYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwMDY3NjgyNiwiaWF0IjoxNjAwNjczMjI2LCJqdGkiOiI2NGMxMDYwMi05MDQ2LTRkZjAtYTYwNy0xYmM2ZWZkMzQxOTQiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.H-B-0hTQUXBNofyVgViRQnQ4pB86XrRsaEDUHkfun6E-ATc967QQX3XlqfgR12jPupQ9-AIogn8XlAkguqvFR6SvDY5cnJ_X5L1cGjvYT7ABk6OO7flQyLrBZpk4P5HgsbHyKquA6Zv1yI4hGu4asqdZMvksVaB9woLQ_dW1nizau4zIhEamqlv1TpvRaikeueiMJq_jWRoMZcYipq9w88lnWtyQDDIh--0foR4MveFGSrrpfhEDTiz3OPJMZtRLJXrZrB5JYOjnePz-o1-zCDlwEUvpntRQ4qVUl5tFKlUP5UmMsuRXJctEinMC8G5Nw86BMJCEcO4Jjlfcbq6Y1A"
	output, err := p1.ChangePassword(&cip.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: password,
		ProposedPassword: password,
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
	   {

	   }
	*/
}

func TestForgotPassword(t *testing.T) {
	output, err := p1.ForgotPassword(&cip.ForgotPasswordInput{
		ClientId: clientId,
		Username: username,
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
	   {
	     CodeDeliveryDetails: {
	       AttributeName: "email",
	       DeliveryMedium: "EMAIL",
	       Destination: "s***@g***.com"
	     }
	   }
	*/
}

func TestConfirmForgotPassword(t *testing.T) {
	output, err := p1.ConfirmForgotPassword(&cip.ConfirmForgotPasswordInput{
		ClientId:         clientId,
		Username:         username,
		ConfirmationCode: aws.String("921335"),
		Password:         password,
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
		{

		}
	*/
}

func TestGlobalSignOut(t *testing.T) {
	accessToken := "eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJldmVudF9pZCI6ImI5ODIwYzY1LTk4N2YtNDBjMS1hNGM2LTgxNjE3NzNiOGFjYyIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDA2NzMwNTAsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwMDY3NjY1MCwiaWF0IjoxNjAwNjczMDUwLCJqdGkiOiI0NThlYWI2Yy04MzYzLTQ0OTYtYWUwOS0yMmQ1OTc5ZTQwMTEiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.UOpdScT_WpknQg9iZpPe-MAw4DEAhhwdO9IAyydwLxeC3nGbKO954DSjRVZI19ZkO4oeU3tF8e9R4Iqvork-7G2F4jQPr8rCXd5fvGdNVWhvRnthdF4yUscB8O593a9cb6LaS3Dx_E3SSlJsxn3CLUS9sLMcVYx6rt_u_bKymJ9XOOP3ZptmTHj32mTtO-yAGO_SUzw71smoN_QiAkYk3EGwT4fRStoy-xcopdcpdjr_kXn-kZtB9kqpcMBDJYFQNvXQMdMHMJuKfkN3BD5kJH3-4IvfW_bHnLug4J1ZzQgIsJqrUQs-qLedD-MADUJt3FE69RGW8TjVNwugWCt3hA"
	output, err := p1.GlobalSignOut(&cip.GlobalSignOutInput{
		AccessToken: aws.String(accessToken),
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
		{

		}
	*/
}

func TestResendConfirmationCode(t *testing.T) {
	output, err := p1.ResendConfirmationCode(&cip.ResendConfirmationCodeInput{
		ClientId: clientId,
		Username: aws.String("felix"),
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
		{
		  CodeDeliveryDetails: {
		    AttributeName: "email",
		    DeliveryMedium: "EMAIL",
		    Destination: "s***@g***.com"
		  }
		}
	*/
}

func TestInitAuth(t *testing.T) {
	output, err := p1.InitiateAuth(&cip.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String("felix"),
			"PASSWORD": password,
		},
		ClientId: clientId,
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}

	/*
		{
		  AuthenticationResult: {
		    AccessToken: "eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJldmVudF9pZCI6IjAzYTMwZmJhLTY0OGYtNGJmZS04MmNhLTBjOTk2OTFhMWM0YiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDA2NjAzNzYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwMDY2Mzk3NiwiaWF0IjoxNjAwNjYwMzc2LCJqdGkiOiJkMmViYzYzYi00MmI4LTRkMTgtOTE1ZC1mMDkwNzM1M2UyZTkiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.eRkR-k3rj8qwm3NRsDDCxJObY7tvWCnnMdnvCeHyQQP_fSE1oNlCQZV1cxwEQOsmX6oI9DZ-xy2XJiZyisaq2LzMwQk3_IJ30pvK6BnEt5m-ynWpWBHgIyXVw7sMa578NRrWen1lYGmR0s7nxRl1R0dLkxpDVMprNKFvk7L_hOYWKA7B3XH1id_oB5mwlAZk3D6vDXmUFCoeywowPdgyGMx1R3uvTt2maPodbHUbTItbsQ86YMDAhv6kBVeZChlwhio9Pb4IpPjxltPVpsyEAAwIb2R8vkb4VDWTPCfQVMrXwvMrYDDT5YNLWZScVaEhBAxwUB03JBG0virQRFp17w",
		    ExpiresIn: 3600,
		    IdToken: "eyJraWQiOiJod3c2WjNmNmxLeEZHMjU5YVRlZXFCTXlPRzVTeHM2Q1wvM2pxRVV3Z2NvUT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJhdWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjAzYTMwZmJhLTY0OGYtNGJmZS04MmNhLTBjOTk2OTFhMWM0YiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjAwNjYwMzc2LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9CMXNGdmM0akkiLCJjb2duaXRvOnVzZXJuYW1lIjoiZmVsaXgiLCJleHAiOjE2MDA2NjM5NzYsImlhdCI6MTYwMDY2MDM3NiwiZW1haWwiOiJzdW5mbWluQGdtYWlsLmNvbSJ9.XgLtVWr1vnCQ2jgQOOKRSCrzTyCnevh0MmmgMvnHB_uq1rJgFzr6Hx--xDqwQx2mYI98w4h0YDnHPmRGxGU2v9mAxfojX5ihgA836KvpMkCs4nwcztYEPKmiyOWpQYBugsZaDtnROlS1nm6vvZs5E4EMNpwVeyNLRbZs22wpieIZcNygcoaq9EcbzHPLkQYaqCxfzrQeC1zZbKKd-bbUuuPlWGzasLd-Yy07i2YoYBL8egHJHyqMU_CUvKmc6qcYP6saHlYsMbC8_Reoho0A1aviY0g2LFdKaPjZ_IFP94SeCYbWhtDGJNhzan_vlIwfVpBVEHCSdunSW-X9u9WGlA",
		    RefreshToken: "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.PKdWLIKNHQAfiLRebFm7NkqA2c_TgfTqMfrGgG0sTgo9xHlUmTaVRzgabB1h9xCEflBxnWPyOQ_mcA0fp5veYP-Osk36aHBx3hqK0jY3X9wMP33HeMntdTf8AI-MicL-i-71sO-7FCElpZym96QdLSY7pe31rDtH6qeuSSBejyyX19ACZW7Tsd5E_HZnzxka3YHuIvsaUuEJ1RB_7KDjBZ1Ut_zoy5TO00Wy1hmPT-S8KTJ0s6GjukSk-rpo6wnvwP-H___tG19QC4is2_nr5fcrtYGQfO-nF40_65ZCA1UFopxMyBlF_TGm3gvSkH-Kherr2FSH6INPyYUNA933Nw.uI5qFxKoGA8dr5BG.N5CvxmzTft2BtDFvtmJ4Qc4xMx_ZCHzcH_1OThll9OzH1ERtZWwAGW0z0pWHsAZH5eLsVLtUoRXhlxCh0itRMqNHXjhiU0BPvtfGCufiqKu3xkpTs0BBCw51w3AJJ2znH94QxZefa8qFIwMEa7lMuAr0pxm5v4j6q8Vs3AgaBiB9kryM8tdDoektn4MESRU4-Hl8OaTvqbEP-eBPeD9OSbnc1GAu8GUAEqIOSROck48CUlpfnZY0lGS8uWUAfJ5OE-lJMHIbWdsP-_Au7YemBZeZrO-j-S8B7OjQimeRwXXRXzE6oAaWNx_fqlnbWa1fw1QMETPqrg3rdBScazKrC81kgmp_SX2RouH54zFP-U7at6wjNxCR6ZMjovTlLyY2UigkdUk1SVCGSm3dhNuXU486CsL1FuhwCCQjw1Qo3OkGgYjgUhTMp4DiJ_A8Sfhcv2wAkdbAn82DntlKz64YFvQKylXuecXRl2K2CKVtE6FoxxTJG9T5JYPm-jrnyW9oooPkiB9jiY8M2qbed22YwQVRPeaiL_3FscCB8IhlIyfwz97s78ck_gUo1QyRPsKbGJz5L3cPi8GJn54Lv8azKoqqJIEqFndIbBjplVUcMRhYsTyNdSl2S8w8mONi_U7ufHilNFyppYXgI_8V1Nji2C2edqaMFF5L1qI8VeqU93nPjalOzrp5qe31NpJZB7G7e37BUWSom-a9W5_ux1ekHaCpXbWjls4RxYQvaXtyxL8RPSirbPl5MwQrpFFWGuechy4a4g478v-oq8JYu2ibuuioJxvVySDLhdgO2puJqTGuNzqQ8m-UUFv2B0PsPQlrnL2-aNeshvYo-NQMSk17Z2bMxRKTEbFIp9eseyAqUlI6rH0vncFieNLNTsKYIsfCi2uKhrdQX_LIRkChNB7GGQXeoDJ5L8TwrK7swxgWx_ygy5BscSesp4iDrcie7rCy1c4h0ospHu7KsSmYL4hxDDSjJyIC3pnK3Lp2n3xfI19-A3ryMOVoxBvyGDwv3X0BB6YOKlQgWuQ16W-Qz70fGxVMf0n6RLaSJC5U0lxsci42orSmllT7_0tgwLdhn8zOLzumlKEGkkP_bsjOHpRfFo3tTldbYPgMuigNdl8pmaqAKNutMHqBaooWxNNmLZ0OShBMb6TL8Qt5e4mUpwz0yM2o-7WcX89Yj8DPgE1nbWTxu5zGJp4Wr5U9C2ErsTpj8Upqld7t8zNY6UJK4Y9D0f7Vz7jO68U-VoHiIGOtHtgiPnm_ZyDut_GESFM1rQ7A8aE.3JmV8fDOekrAoxDwTNIgdg",
		    TokenType: "Bearer"
		  },
		  ChallengeParameters: {

		  }
		}
	*/
}

func TestCheckTokens(t *testing.T) {
	accessToken := "eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJldmVudF9pZCI6IjAzYTMwZmJhLTY0OGYtNGJmZS04MmNhLTBjOTk2OTFhMWM0YiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDA2NjAzNzYsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwMDY2Mzk3NiwiaWF0IjoxNjAwNjYwMzc2LCJqdGkiOiJkMmViYzYzYi00MmI4LTRkMTgtOTE1ZC1mMDkwNzM1M2UyZTkiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.eRkR-k3rj8qwm3NRsDDCxJObY7tvWCnnMdnvCeHyQQP_fSE1oNlCQZV1cxwEQOsmX6oI9DZ-xy2XJiZyisaq2LzMwQk3_IJ30pvK6BnEt5m-ynWpWBHgIyXVw7sMa578NRrWen1lYGmR0s7nxRl1R0dLkxpDVMprNKFvk7L_hOYWKA7B3XH1id_oB5mwlAZk3D6vDXmUFCoeywowPdgyGMx1R3uvTt2maPodbHUbTItbsQ86YMDAhv6kBVeZChlwhio9Pb4IpPjxltPVpsyEAAwIb2R8vkb4VDWTPCfQVMrXwvMrYDDT5YNLWZScVaEhBAxwUB03JBG0virQRFp17w"
	idToken := "eyJraWQiOiJod3c2WjNmNmxLeEZHMjU5YVRlZXFCTXlPRzVTeHM2Q1wvM2pxRVV3Z2NvUT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZDJhMDcwYi1iOGRiLTRhNmEtOTVhMi0yOWIyOTBmMDcwOWUiLCJhdWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjAzYTMwZmJhLTY0OGYtNGJmZS04MmNhLTBjOTk2OTFhMWM0YiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjAwNjYwMzc2LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9CMXNGdmM0akkiLCJjb2duaXRvOnVzZXJuYW1lIjoiZmVsaXgiLCJleHAiOjE2MDA2NjM5NzYsImlhdCI6MTYwMDY2MDM3NiwiZW1haWwiOiJzdW5mbWluQGdtYWlsLmNvbSJ9.XgLtVWr1vnCQ2jgQOOKRSCrzTyCnevh0MmmgMvnHB_uq1rJgFzr6Hx--xDqwQx2mYI98w4h0YDnHPmRGxGU2v9mAxfojX5ihgA836KvpMkCs4nwcztYEPKmiyOWpQYBugsZaDtnROlS1nm6vvZs5E4EMNpwVeyNLRbZs22wpieIZcNygcoaq9EcbzHPLkQYaqCxfzrQeC1zZbKKd-bbUuuPlWGzasLd-Yy07i2YoYBL8egHJHyqMU_CUvKmc6qcYP6saHlYsMbC8_Reoho0A1aviY0g2LFdKaPjZ_IFP94SeCYbWhtDGJNhzan_vlIwfVpBVEHCSdunSW-X9u9WGlA"

	resp, err := http.Get("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B1sFvc4jI/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}

	krBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var keys jwt.KeyRegister
	_, err = keys.LoadJWK(krBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := keys.Check([]byte(accessToken))

	if err != nil {
		t.Error(err)
	}
	fmt.Printf("access token claims: %#v\n", claims)

	/*
		&jwt.Claims{
			Registered: jwt.Registered{
				Issuer:    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B1sFvc4jI",
				Subject:   "bd2a070b-b8db-4a6a-95a2-29b290f0709e",
				Audiences: []string(nil),
				Expires:   (*jwt.NumericTime)(0xc0003751a8),
				NotBefore: (*jwt.NumericTime)(nil),
				Issued:    (*jwt.NumericTime)(0xc0003751b8),
				ID:        "d2ebc63b-42b8-4d18-915d-f0907353e2e9",
			},
			Set: map[string]interface{}{
				"auth_time": 1.600660376e+09,
				"client_id": "2knvrtld8j6cosq7e477rhdu5j",
				"event_id":  "03a30fba-648f-4bfe-82ca-0c99691a1c4b",
				"scope":     "aws.cognito.signin.user.admin",
				"token_use": "access",
				"username":  "felix",
			},
			Raw:   json.RawMessage{0x7b, 0x22},
			KeyID: "NYzefDcehJK4sF8LxiFZyRfww32vjH13kubYgUEPqfc=",
		}
	*/

	idTokenClaims, err := keys.Check([]byte(idToken))
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("id token claims: %#v\n", idTokenClaims)

	/*
		&jwt.Claims{
			Registered: jwt.Registered{
				Issuer:    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B1sFvc4jI",
				Subject:   "bd2a070b-b8db-4a6a-95a2-29b290f0709e",
				Audiences: []string{"2knvrtld8j6cosq7e477rhdu5j"},
				Expires:   (*jwt.NumericTime)(0xc000378980),
				NotBefore: (*jwt.NumericTime)(nil),
				Issued:    (*jwt.NumericTime)(0xc000378990),
				ID:        "",
			},
			Set: map[string]interface{}{
				"auth_time":        1.600660376e+09,
				"cognito:username": "felix",
				"email":            "sunfmin@gmail.com",
				"email_verified":   true,
				"event_id":         "03a30fba-648f-4bfe-82ca-0c99691a1c4b",
				"token_use":        "id",
			},
			Raw:   json.RawMessage{0x7b, 0x22},
			KeyID: "hww6Z3f6lKxFG259aTeeqBMyOG5Sxs6C/3jqEUwgcoQ=",
		}
	*/
}
