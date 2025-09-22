package viewer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromClaims(t *testing.T) {
	claims := map[string]any{
		"sub":                "1d2e3000-8eba-4c30-9a09-1ca7c00df751",
		"preferred_username": "dalu",
		"email":              "info@icod.de",
		"name":               "Darko Luketic",
		"given_name":         "Darko",
		"family_name":        "Luketic",
		"realm_access": map[string]any{
			"roles": []any{"default-roles-dev", "offline_access", "uma_authorization"},
		},
		"resource_access": map[string]any{
			"account": map[string]any{
				"roles": []any{"manage-account", "manage-account-links", "view-profile"},
			},
		},
		"scope": "openid email profile",
	}

	v := FromClaims(claims)

	require.Equal(t, "1d2e3000-8eba-4c30-9a09-1ca7c00df751", v.Subject)
	require.Equal(t, "dalu", v.PreferredUsername)
	require.Equal(t, "info@icod.de", v.Email)
	require.Equal(t, "Darko", v.GivenName)
	require.Equal(t, "Luketic", v.FamilyName)
	require.Equal(t, []string{"default-roles-dev", "offline_access", "uma_authorization"}, v.RealmRoles)
	require.Equal(t, map[string][]string{
		"account": []string{"manage-account", "manage-account-links", "view-profile"},
	}, v.ResourceRoles)
	require.Equal(t, []string{"openid", "email", "profile"}, v.Scopes)

	// Mutating the original claims after construction should not affect the viewer.
	claims["preferred_username"] = "other"
	require.Equal(t, "dalu", v.PreferredUsername)

	// RawClaims must return a defensive copy.
	raw := v.RawClaims()
	raw["sub"] = "changed"
	require.Equal(t, "1d2e3000-8eba-4c30-9a09-1ca7c00df751", v.RawClaims()["sub"])
}

func TestViewerAuthorizationHelpers(t *testing.T) {
	v := FromClaims(map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"admins", "Operators"},
		},
		"resource_access": map[string]any{
			"service": map[string]any{
				"roles": []any{"Reader", "writer"},
			},
		},
		"scp": []any{"payments.read", "payments.write"},
	})

	require.True(t, v.HasRealmRole("admins"))
	require.True(t, v.HasRealmRole("operators"))
	require.False(t, v.HasRealmRole("missing"))

	require.True(t, v.HasResourceRole("service", "reader"))
	require.True(t, v.HasResourceRole("service", "WRITER"))
	require.False(t, v.HasResourceRole("service", "viewer"))
	require.False(t, v.HasResourceRole("other", "reader"))

	require.True(t, v.HasAnyScope("payments.read"))
	require.True(t, v.HasAnyScope("payments.delete", "payments.write"))
	require.False(t, v.HasAnyScope("payments.delete"))
}

func TestContextHelpers(t *testing.T) {
	v := FromClaims(map[string]any{"sub": "subject"})

	ctx := WithViewer(context.Background(), v)

	fetched, err := FromContext(ctx)
	require.NoError(t, err)
	require.Equal(t, v, fetched)

	require.Panics(t, func() {
		MustFromContext(context.Background())
	})

	_, err = FromContext(context.Background())
	require.ErrorIs(t, err, ErrNoViewer)
}
