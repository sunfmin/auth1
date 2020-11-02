package aws_cognito_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	cid "github.com/aws/aws-sdk-go/service/cognitoidentity"
)

var ci = cid.New(sess, aws.NewConfig().WithRegion("us-east-1"))

var identityPoolId = aws.String("us-east-1:c06995d7-5a80-4a65-9965-124fb03e83a0")

func TestGetId(t *testing.T) {
	output, err := ci.GetId(&cid.GetIdInput{
		AccountId:      aws.String("180909087256"),
		IdentityPoolId: identityPoolId,
		Logins: map[string]*string{
			"cognito-idp.us-east-1.amazonaws.com/us-east-1_B1sFvc4jI": aws.String("eyJraWQiOiJOWXplZkRjZWhKSzRzRjhMeGlGWnlSZnd3MzJ2akgxM2t1YllnVUVQcWZjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2MDY5MGZmZi1jYjhmLTRmNTktODM0Zi1lZWI0ZWY4MTIyMjciLCJldmVudF9pZCI6ImYzOWUzNDI0LWU4ZmQtNGY4Zi1iYTUxLTAyM2Q5NGVkNWExMyIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDQzMDk4MjcsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0Ixc0Z2YzRqSSIsImV4cCI6MTYwNDMxMzQyNywiaWF0IjoxNjA0MzA5ODI3LCJqdGkiOiJkMDY1MDYzMy02Yjg5LTQyNjItYTk1Yy04MWY0ODg2ZDFhMTkiLCJjbGllbnRfaWQiOiIya252cnRsZDhqNmNvc3E3ZTQ3N3JoZHU1aiIsInVzZXJuYW1lIjoiZmVsaXgifQ.bSX-ItziBkKgWKTHF-_BftD9RSTQwi3q1d4Bn1tig7jBVw-0pYFlsBjc3J7Gq2rNcd8IXK7ISzBOs0ojTa1DK9d_f-heltaFJhuwVjGDyJXBENo531SkwlK0shA_G7b8GeiAfiG0088iFm96qwFIf-RA0n_ufL_G3Z8D0RlUxoxu33-rQGEMJbMvk85C-3n2aai16DMrw-UmSRTB5Zu8b-zuVnVnhB3X5wRWg18VwmkVtIsPwJTH5zoob-vH0DFUrGtRDtcjNEvpd9iQPtwEduYy8x1sWC0ldo3xRqTGfai6w9wdg5663j6B6mgH2K8C1CNNNLERjVrB3VmPT_WyDg"),
		},
	})

	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v", output)
}
