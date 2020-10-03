package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/field"
	"github.com/google/uuid"
	"github.com/sunfmin/auth1/gql/api"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}),
		field.String("username").Unique(),
		field.String("phone_number").Unique(),
		field.String("email").Unique(),
		field.String("password_hash").Optional(),
		field.String("confirmation_code_hash").Optional(),
		field.JSON("user_attributes", []*api.AttributeType{}).Optional(),
		field.Int("active_state").Optional(),
		field.String("code_time").Optional(),
		field.Int("token_state").Optional(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return nil
}
