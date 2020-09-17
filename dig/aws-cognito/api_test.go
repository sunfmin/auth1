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

func TestSignUp(t *testing.T) {

	tryDeleteUser("felix")
	output, err := p1.SignUp(&cip.SignUpInput{
		ClientId: clientId,
		Username: aws.String("felix"),
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
		Password: aws.String("12345678abcA@"),
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
		ConfirmationCode: aws.String("700236"),
	})

	fmt.Println(output, err)
	if err != nil {
		t.Error(err)
	}
}
