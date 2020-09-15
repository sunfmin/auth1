package aws_cognito_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func TestSignUp(t *testing.T) {
	sess := session.Must(session.NewSession(aws.NewConfig().
		WithMaxRetries(3),
	))

	p1 := cip.New(sess, aws.NewConfig().WithRegion("us-east-1"))

	output, err := p1.SignUp(&cip.SignUpInput{
		ClientId: aws.String("24vt1bv6p0a17njnno8j85c198"),
		Username: aws.String("felix"),
		Password: aws.String("123456"),
	})
	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}
}
