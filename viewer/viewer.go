package viewer

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
)

type contextKey string

const viewerContextKey contextKey = "oidcmw-viewer"

// ErrNoViewer indicates that no viewer was present in a context.
var ErrNoViewer = errors.New("viewer: viewer not found in context")

// Viewer represents the authenticated caller derived from validated token claims.
type Viewer struct {
	Subject           string
	PreferredUsername string
	Email             string
	Name              string
	GivenName         string
	FamilyName        string
	RealmRoles        []string
	ResourceRoles     map[string][]string
	Scopes            []string

	rawClaims map[string]any
	lowerSets lowerCaseSets
}

type lowerCaseSets struct {
	realmRoles    map[string]struct{}
	resourceRoles map[string]map[string]struct{}
	scopes        map[string]struct{}
}

// FromClaims constructs a Viewer from validated token claims.
func FromClaims(claims map[string]any) *Viewer {
	cloned := cloneClaims(claims)

	viewer := &Viewer{
		Subject:           stringClaim(cloned, "sub"),
		PreferredUsername: stringClaim(cloned, "preferred_username"),
		Email:             stringClaim(cloned, "email"),
		Name:              stringClaim(cloned, "name"),
		GivenName:         stringClaim(cloned, "given_name"),
		FamilyName:        stringClaim(cloned, "family_name"),
		RealmRoles:        parseRealmRoles(cloned),
		ResourceRoles:     parseResourceRoles(cloned),
		Scopes:            parseScopes(cloned),
		rawClaims:         cloned,
	}

	viewer.lowerSets = buildLowerSets(viewer)

	return viewer
}

// RawClaims returns a copy of the underlying claims used to construct the Viewer.
func (v *Viewer) RawClaims() map[string]any {
	if v == nil {
		return nil
	}
	return cloneClaims(v.rawClaims)
}

// HasRealmRole reports whether the viewer possesses the provided realm role.
func (v *Viewer) HasRealmRole(role string) bool {
	if v == nil {
		return false
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return false
	}
	_, ok := v.lowerSets.realmRoles[role]
	return ok
}

// HasResourceRole reports whether the viewer holds the given role within a resource namespace.
func (v *Viewer) HasResourceRole(resource, role string) bool {
	if v == nil {
		return false
	}
	resource = strings.ToLower(strings.TrimSpace(resource))
	role = strings.ToLower(strings.TrimSpace(role))
	if resource == "" || role == "" {
		return false
	}
	roles, ok := v.lowerSets.resourceRoles[resource]
	if !ok {
		return false
	}
	_, ok = roles[role]
	return ok
}

// HasAnyScope reports whether the viewer has at least one of the requested scopes.
func (v *Viewer) HasAnyScope(scopes ...string) bool {
	if v == nil {
		return false
	}
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if _, ok := v.lowerSets.scopes[scope]; ok {
			return true
		}
	}
	return false
}

// WithViewer stores the viewer inside the context for downstream handlers.
func WithViewer(ctx context.Context, v *Viewer) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, viewerContextKey, v)
}

// FromContext retrieves the viewer from the provided context.
func FromContext(ctx context.Context) (*Viewer, error) {
	if ctx == nil {
		return nil, ErrNoViewer
	}
	viewer, ok := ctx.Value(viewerContextKey).(*Viewer)
	if !ok || viewer == nil {
		return nil, ErrNoViewer
	}
	return viewer, nil
}

// MustFromContext retrieves the viewer from context or panics if it is absent.
func MustFromContext(ctx context.Context) *Viewer {
	viewer, err := FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return viewer
}

// IsAuthenticated reports whether the context contains an authenticated viewer.
func IsAuthenticated(ctx context.Context) bool {
	_, err := FromContext(ctx)
	return err == nil
}

func cloneClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return map[string]any{}
	}
	return maps.Clone(claims)
}

func stringClaim(claims map[string]any, key string) string {
	raw, _ := claims[key].(string)
	return strings.TrimSpace(raw)
}

func parseRealmRoles(claims map[string]any) []string {
	raw, _ := claims["realm_access"].(map[string]any)
	if len(raw) == 0 {
		return nil
	}
	roles := normalizeStringSlice(raw["roles"], true)
	return roles
}

func parseResourceRoles(claims map[string]any) map[string][]string {
	raw, _ := claims["resource_access"].(map[string]any)
	if len(raw) == 0 {
		return nil
	}
	result := make(map[string][]string, len(raw))
	for resource, value := range raw {
		if resource == "" {
			continue
		}
		roleMap, _ := value.(map[string]any)
		roles := normalizeStringSlice(roleMap["roles"], true)
		if len(roles) == 0 {
			continue
		}
		result[resource] = roles
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseScopes(claims map[string]any) []string {
	addSplit := func(destination *[]string, seen map[string]struct{}, value string) {
		for _, scope := range strings.Fields(value) {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			if _, exists := seen[scope]; exists {
				continue
			}
			seen[scope] = struct{}{}
			*destination = append(*destination, scope)
		}
	}

	addList := func(destination *[]string, seen map[string]struct{}, values []string) {
		for _, value := range values {
			addSplit(destination, seen, value)
		}
	}

	var scopes []string
	seen := make(map[string]struct{})

	if raw, ok := claims["scope"]; ok {
		switch v := raw.(type) {
		case string:
			addSplit(&scopes, seen, v)
		case []string:
			addList(&scopes, seen, v)
		case []any:
			addList(&scopes, seen, toStringSlice(v))
		}
	}

	for _, key := range []string{"scp", "scopes"} {
		if raw, ok := claims[key]; ok {
			switch v := raw.(type) {
			case string:
				addSplit(&scopes, seen, v)
			case []string:
				addList(&scopes, seen, v)
			case []any:
				addList(&scopes, seen, toStringSlice(v))
			}
		}
	}

	if len(scopes) == 0 {
		return nil
	}

	return scopes
}

func normalizeStringSlice(value any, dedupe bool) []string {
	list := toStringSlice(value)
	if len(list) == 0 {
		return nil
	}
	trimmed := make([]string, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if dedupe {
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
		}
		trimmed = append(trimmed, item)
	}
	if len(trimmed) == 0 {
		return nil
	}
	sort.Strings(trimmed)
	return trimmed
}

func toStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			switch s := item.(type) {
			case string:
				result = append(result, s)
			}
		}
		return result
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func buildLowerSets(v *Viewer) lowerCaseSets {
	sets := lowerCaseSets{
		realmRoles:    make(map[string]struct{}, len(v.RealmRoles)),
		resourceRoles: make(map[string]map[string]struct{}, len(v.ResourceRoles)),
		scopes:        make(map[string]struct{}, len(v.Scopes)),
	}

	for _, role := range v.RealmRoles {
		sets.realmRoles[strings.ToLower(role)] = struct{}{}
	}

	for resource, roles := range v.ResourceRoles {
		if _, ok := sets.resourceRoles[strings.ToLower(resource)]; !ok {
			sets.resourceRoles[strings.ToLower(resource)] = make(map[string]struct{}, len(roles))
		}
		lowerResource := sets.resourceRoles[strings.ToLower(resource)]
		for _, role := range roles {
			lowerResource[strings.ToLower(role)] = struct{}{}
		}
	}

	for _, scope := range v.Scopes {
		sets.scopes[strings.ToLower(scope)] = struct{}{}
	}

	return sets
}
