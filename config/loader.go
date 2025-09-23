package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deicod/oidcmw/tokensource"
	"gopkg.in/yaml.v3"
)

type fileConfig struct {
	Issuer                 string                 `json:"issuer" yaml:"issuer"`
	Audiences              []string               `json:"audiences" yaml:"audiences"`
	TokenTypes             []string               `json:"token_types" yaml:"token_types"`
	AuthorizedParties      []string               `json:"authorized_parties" yaml:"authorized_parties"`
	ClockSkew              string                 `json:"clock_skew" yaml:"clock_skew"`
	UnauthorizedStatus     int                    `json:"unauthorized_status_code" yaml:"unauthorized_status_code"`
	AllowAnonymousRequests *bool                  `json:"allow_anonymous_requests" yaml:"allow_anonymous_requests"`
	TokenSources           tokenSourceDefinitions `json:"token_sources" yaml:"token_sources"`
}

type tokenSourceDefinitions []tokensource.Definition

func (t *tokenSourceDefinitions) UnmarshalJSON(data []byte) error {
	data = bytesTrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	switch data[0] {
	case '"':
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		defs, err := tokensource.ParseList(raw)
		if err != nil {
			return err
		}
		*t = defs
		return nil
	case '[':
		var defs []tokensource.Definition
		if err := json.Unmarshal(data, &defs); err != nil {
			return err
		}
		*t = defs
		return nil
	default:
		return fmt.Errorf("config: token_sources must be string or array, got %s", string(data))
	}
}

func (t *tokenSourceDefinitions) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case 0:
		return nil
	case yaml.ScalarNode:
		var raw string
		if err := value.Decode(&raw); err != nil {
			return err
		}
		defs, err := tokensource.ParseList(raw)
		if err != nil {
			return err
		}
		*t = defs
		return nil
	case yaml.SequenceNode:
		var defs []tokensource.Definition
		if err := value.Decode(&defs); err != nil {
			return err
		}
		*t = defs
		return nil
	default:
		return fmt.Errorf("config: token_sources must be a sequence or string")
	}
}

// FromFile loads configuration from a JSON or YAML file.
func FromFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: open file: %w", err)
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(path))
	fc, err := decodeFile(file, ext)
	if err != nil {
		return Config{}, err
	}
	return fc.toConfig()
}

func decodeFile(r io.Reader, ext string) (fileConfig, error) {
	var fc fileConfig
	switch ext {
	case ".yaml", ".yml":
		dec := yaml.NewDecoder(r)
		dec.KnownFields(true)
		if err := dec.Decode(&fc); err != nil {
			return fileConfig{}, fmt.Errorf("config: decode yaml: %w", err)
		}
	case ".json", "":
		dec := json.NewDecoder(r)
		if err := dec.Decode(&fc); err != nil {
			return fileConfig{}, fmt.Errorf("config: decode json: %w", err)
		}
	default:
		return fileConfig{}, fmt.Errorf("config: unsupported file extension %q", ext)
	}
	return fc, nil
}

func (fc fileConfig) toConfig() (Config, error) {
	cfg := Config{
		Issuer:            strings.TrimSpace(fc.Issuer),
		Audiences:         cloneStringSlice(fc.Audiences),
		TokenTypes:        cloneStringSlice(fc.TokenTypes),
		AuthorizedParties: cloneStringSlice(fc.AuthorizedParties),
	}
	if fc.ClockSkew != "" {
		d, err := time.ParseDuration(fc.ClockSkew)
		if err != nil {
			return Config{}, fmt.Errorf("config: parse clock_skew: %w", err)
		}
		cfg.ClockSkew = d
	}
	if fc.UnauthorizedStatus != 0 {
		cfg.UnauthorizedStatusCode = fc.UnauthorizedStatus
	}
	if fc.AllowAnonymousRequests != nil {
		cfg.AllowAnonymousRequests = *fc.AllowAnonymousRequests
		cfg.allowAnonymousRequestsConfigured = true
	}
	if len(fc.TokenSources) > 0 {
		for _, def := range fc.TokenSources {
			src, err := def.Build()
			if err != nil {
				return Config{}, err
			}
			cfg.TokenSources = append(cfg.TokenSources, src)
		}
	}
	return cfg, nil
}

// FromEnv constructs configuration from environment variables using the provided prefix.
func FromEnv(prefix string) (Config, error) {
	if prefix != "" && !strings.HasSuffix(prefix, "_") {
		prefix += "_"
	}
	lookup := func(key string) (string, bool) {
		return os.LookupEnv(prefix + key)
	}
	cfg := Config{}
	if v, ok := lookup("ISSUER"); ok {
		cfg.Issuer = strings.TrimSpace(v)
	}
	if v, ok := lookup("AUDIENCES"); ok {
		cfg.Audiences = splitAndTrim(v)
	}
	if v, ok := lookup("TOKEN_TYPES"); ok {
		cfg.TokenTypes = splitAndTrim(v)
	}
	if v, ok := lookup("AUTHORIZED_PARTIES"); ok {
		cfg.AuthorizedParties = splitAndTrim(v)
	}
	if v, ok := lookup("CLOCK_SKEW"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return Config{}, fmt.Errorf("config: parse CLOCK_SKEW: %w", err)
		}
		cfg.ClockSkew = d
	}
	if v, ok := lookup("UNAUTHORIZED_STATUS_CODE"); ok {
		code, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return Config{}, fmt.Errorf("config: parse UNAUTHORIZED_STATUS_CODE: %w", err)
		}
		cfg.UnauthorizedStatusCode = code
	}
	if v, ok := lookup("ALLOW_ANONYMOUS_REQUESTS"); ok {
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return Config{}, fmt.Errorf("config: parse ALLOW_ANONYMOUS_REQUESTS: %w", err)
		}
		cfg.AllowAnonymousRequests = parsed
		cfg.allowAnonymousRequestsConfigured = true
	}
	if v, ok := lookup("TOKEN_SOURCES"); ok {
		defs, err := tokensource.ParseList(v)
		if err != nil {
			return Config{}, err
		}
		for _, def := range defs {
			src, err := def.Build()
			if err != nil {
				return Config{}, err
			}
			cfg.TokenSources = append(cfg.TokenSources, src)
		}
	}
	return cfg, nil
}

// Merge applies overrides to a base configuration. Zero-value fields in overrides are ignored.
func Merge(base Config, overrides ...Config) Config {
	result := base
	for _, override := range overrides {
		if override.Issuer != "" {
			result.Issuer = override.Issuer
		}
		if len(override.Audiences) > 0 {
			result.Audiences = cloneStringSlice(override.Audiences)
		}
		if len(override.TokenTypes) > 0 {
			result.TokenTypes = cloneStringSlice(override.TokenTypes)
		}
		if len(override.AuthorizedParties) > 0 {
			result.AuthorizedParties = cloneStringSlice(override.AuthorizedParties)
		}
		if override.ClockSkew != 0 {
			result.ClockSkew = override.ClockSkew
		}
		if override.UnauthorizedStatusCode != 0 {
			result.UnauthorizedStatusCode = override.UnauthorizedStatusCode
		}
		if override.ErrorResponseBuilder != nil {
			result.ErrorResponseBuilder = override.ErrorResponseBuilder
		}
		if override.Now != nil {
			result.Now = override.Now
		}
		if override.allowAnonymousRequestsConfigured {
			result.AllowAnonymousRequests = override.AllowAnonymousRequests
			result.allowAnonymousRequestsConfigured = true
		}
		if len(override.TokenSources) > 0 {
			result.TokenSources = append([]tokensource.Source(nil), override.TokenSources...)
		}
		if len(override.ClaimsValidators) > 0 {
			result.ClaimsValidators = append(result.ClaimsValidators, override.ClaimsValidators...)
		}
	}
	return result
}

// LoadOptions configures the Load helper.
type LoadOptions struct {
	Base      Config
	File      string
	EnvPrefix string
}

// Load composes configuration from file and environment sources.
func Load(opts LoadOptions) (Config, error) {
	cfg := opts.Base
	if opts.File != "" {
		fileCfg, err := FromFile(opts.File)
		if err != nil {
			return Config{}, err
		}
		cfg = Merge(cfg, fileCfg)
	}
	if opts.EnvPrefix != "" {
		envCfg, err := FromEnv(opts.EnvPrefix)
		if err != nil {
			return Config{}, err
		}
		cfg = Merge(cfg, envCfg)
	}
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

func splitAndTrim(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\t' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\t' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}
