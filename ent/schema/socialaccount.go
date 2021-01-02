package schema

import  (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/field"
	"github.com/google/uuid"
)

// SocialAccount holds the schema definition for the SocialAccount entity.
type SocialAccount struct {
	ent.Schema
}
type identities struct {
	identities map[string]interface{} 
}
// Fields of the SocialAccount.
func (SocialAccount) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}),
		field.String("user_id").Optional(),
		field.String("username").Unique(),
		field.String("email").Optional(),
		field.String("phone_number").Optional(),
		field.String("idp_identifier").Optional(),
		field.JSON("identities", identities{}.identities).Optional(),
		field.Int("token_state").Optional(),
	}
}

// Edges of the SocialAccount.
func (SocialAccount) Edges() []ent.Edge {
	return nil
}
