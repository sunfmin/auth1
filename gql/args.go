package gql

import (
	"context"

	"github.com/sunfmin/auth1/gql/api"
)

type Args struct {
	AllowSignInWithVerifiedEmailAddress bool
	AllowSignInWithVerifiedPhoneNumber  bool
	AllowSignInWithPreferredUsername    bool
	PreSignUpFunc                       func(ctx context.Context, input api.SignUpInput) error
}
