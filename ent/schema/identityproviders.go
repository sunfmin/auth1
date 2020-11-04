package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/field"
	"github.com/google/uuid"
)

// IdentityProviders holds the schema definition for the IdentityProviders entity.
type IdentityProviders struct {
	ent.Schema
}

// Fields of the IdentityProviders.
func (IdentityProviders) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}),
		field.String("attribute_mapping").Optional(),
		field.String("provider_name").Unique(),
		field.String("provider_type").Unique(),
		field.String("creation_date").Unique(),
		field.String("last_modified_date").Unique(),
		field.String("client_id").Unique(),
		field.String("client_secret").Unique(),
		field.String("authorize_scopes").Optional(),
		field.String("provider_details").Unique(),
	}
}

// Edges of the IdentityProviders.
func (IdentityProviders) Edges() []ent.Edge {
	return nil
}
