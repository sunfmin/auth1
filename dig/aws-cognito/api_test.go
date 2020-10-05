package aws_cognito_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
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
		Username:         aws.String("felix"),
		ConfirmationCode: aws.String("011862"),
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}
}

func TestInitAuth(t *testing.T) {
	output, err := p1.InitiateAuth(&cip.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String("felix1"),
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
		    AccessToken: "eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI1MmYxYjBlOC1hY2U1LTQ5ZWQtOWY5Mi01NDlhZmRhYzcwZmEiLCJldmVudF9pZCI6Ijg3YTY5OTYwLTJiYmEtNDQ3MS05M2EyLWNkY2U1ZTdjZmVmNiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDA0MTczNzMsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwMDQyMDk3MywiaWF0IjoxNjAwNDE3MzczLCJqdGkiOiI4OWQ2ZWNiYS1hYTA0LTQxNzktYWYxMi0xMTJhZDVmN2Y2MTEiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.U0ka1Yjg8meZpixP1jN3sp6mLJ6fDruDy6qC99kF10enoHLaIfCeTDxy_Jm9HIIjQYE61UHhY-TJnq5OugcNEroTLPKjSW_LVJgaB5tCI8E-H8B3OqW5XXLoGHb-T1a981BzebHyGTmhNiNB220N2EyQBKOJnDjSXTgx9r72W-45VoOCgZATzzGexa3AiFxzQYl-ixJ7yajluwPEjG9f7SVxQJwxKqoDvb3JIo6BYlUCktP-lbgB-DG9AWQgWJrbm05jHQu-mJFQARG60XNqORikVAmB4_YjWRQUz9EHfBnesrNQk1lafLgOVRDeUS9o_YuSyJR6LgYheeccXerEPg",
		    ExpiresIn: 3600,
		    IdToken: "eyJraWQiOiJod3c2WjNmNmxLeEZHMjU5YVRlZXFCTXlPRzVTeHM2Q1wvM2pxRVV3Z2NvUT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI1MmYxYjBlOC1hY2U1LTQ5ZWQtOWY5Mi01NDlhZmRhYzcwZmEiLCJhdWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6Ijg3YTY5OTYwLTJiYmEtNDQ3MS05M2EyLWNkY2U1ZTdjZmVmNiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjAwNDE3MzczLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9CMXNGdmM0akkiLCJjb2duaXRvOnVzZXJuYW1lIjoiZmVsaXgiLCJleHAiOjE2MDA0MjA5NzMsImlhdCI6MTYwMDQxNzM3MywiZW1haWwiOiJzdW5mbWluQGdtYWlsLmNvbSJ9.LVLzwJ9uKhN0584zs-P4YlMCB9xXXD8dYyCeaEXRfVT_-lihggiaSMCgWCC7p3YdDZ-bmTaZ8U-kvQhU07PzRurgS1HZVkHBOcXlWz08whtU-0yqifK9ikIuSkO6OYPGyBIehrda2SaNBqNvp5ApVrGnVUWVDTKatWqkMEFa0m5DXa9x_CgzY5XE4tY6wpmkd_sI-zhlYYeni5Iby3doD_MFQWAQ622nr7aZHF9D-KzjpmjA3FKzW43TtSCb88_X-Ogh4Qh7V5S11jVX0baJMANKHmbHrlQZ7yhiruoOyCt3QyAuNJUi0YsiPl-h69kyU2R0fTuMk2Z5W0YKjrQOZw",
		    RefreshToken: "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.a2RMhH-Qm0YMzbr7-gtIRB-Wn_mRK6YujFHi-ZQUsksHoRuO5DT9lW8inpRw6sASCqh5RiPstA0YL9uVMoJFWVl6dSdAf-qmdIw34QzNkZQgThHlNd4yFxV5FUC932OJN3kIHxi8LiUzp_7_D4g4TLAssekc4LMcZG2wr-zlYqtO5qAlJWngomFV5gfukn7X_sZYrlwiq35o4wK131UbT2SmRkC1dAIW0oFjJibzx82PIJn8UD9NNbc3ofKJDDvVnjoJjdzzpr3WWAig7KUey3CY_rWmHXHx41aWQZ3wQGNX9taT6KGX-Su9cmd4JhvywTzSMdGgl53W4t0FIAS-2g.KjOR_PHL_MyvRI29.-UWp0-owM4_H35jfbHB6YSZyqfNTxq1_dZTdqPgo2sAD04MZZR4b_x-vBIH5p7l-RW76MyHmngBAF5qeIdDOouEZR0BRI0u5IwvdlvhSzWyjaNCkY50UxDoZJNeSAPhu8VTVteUO6HUC3Ub2DbKaN4QRJvdmcFPe8fhb6oU1El6f-U555PnNCTdZmP0jkxObzpZHEUiGFTlFMV_ikHrMJ71bcDXRlFg97HjPB5_f6Lb5d4UJjCB4WkYqfcLc3XEZM08JSldz1oHspOyz8cgDXYwvtVXebpZ1Sk3EtwxwpngmNLr_-EzKE2uk55oLj8fWpsuCG4IeidIkVvhwfQlr6agQXwbMcfsAMdlO7aZLyV96IiMtfLnoX38gphoakiErhe19WXt74eeb_9C4cCSYTN4OuJlXLVbyn0cAj3VA6MhUa5EX2Xv92KQok0da68tPTgu-dHYTZPA32ngpG-D-SPvXsd1mpI6hflhX9gWRTWn3deaE73sGg7raehtKWiKMfjQPKzA3I5x8JCdXIOAk1mSPUhstnXlA6XEMkovKczjm5gA5veKVH5Z-NfWEr9nKoN4UJDraSPxYa9nyoBmvaxpTE7waQ866_vpooUnGkZ330l9khplevut66GmWU2oG2av92pTaHh0HP102ggIMMWjOUG05jG2_-QT66p8M23RjoxTUuBLFAuaRV53TplteFltF5LhvJCiBKm-CeqVU1Fe310PfRgS2Z4K_1JbRTuQvoEYzsGHYmTEjkcbT5xNdD_ReYywPSNngTyUV2YNyPzv6Q1EauHw8BDYopcXhOZwpJkOIJCND3gQ4ls2whYCPKsYude2T2Aviuv0f3kR7TNGBUNCnRGKGUJAD6lhDEsSyXsnWxuqpMQfKdcg0x8BzTiOZ6mA0gyYPPSA261HoGMk1uSp8dGPxXkWzj_6ctXO4ZnFQ06sFvtXrIeg8inIl6zPSRVwWXJAJbItnrr5A8qp1bQMToLg7i7k-0S2e_2mbolwgxxOLgoAkfLl_WY6V439Zco5CA3MkcRFDZifZqJ3q0chmuvdF5p0Q9WnbYPqp7afclMIJPWxP49S0UhACpSkSx2cRR-0zRH4QX3axSsVNXV4YZVESXRVjKq7Bmp9se-ygMvMvS61RmFJHe3KdQduDyu-eZ3BUZdMcH_1DEAdsSO6V8JsidzJEySYvZW7w4RZq_sE4_gf2r3xtBRf2B7492RHtcdNfHhUEas0SNR1ghKNh9AhG4qSxYBxY4VQDSw21qHNFkFjm9_ZxrRTGgsQ.GOnMRtZ8xRSVlZL_eiVOOA",
		    TokenType: "Bearer"
		  },
		  ChallengeParameters: {

		  }
		}
	*/
}
