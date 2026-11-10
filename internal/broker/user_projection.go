package broker

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/parser"
	"github.com/expr-lang/expr/vm"
)

const (
	projectionMaxTokenBytes      = 256
	projectionMaxInputBytes      = 64 * 1024
	projectionMaxExpressionBytes = 2048
	projectionMaxNodes           = 256
	projectionMaxPatternBytes    = 256
	projectionMemoryBudget       = 4096
	projectionDefaultMaxTags     = 128
	projectionMaxTags            = 1024
)

// UserProjection is literal configuration, compiled once per configuration load.
// Name deliberately supports only identity-preserving forms; tag rules use a
// bounded expression subset. See docs/design/user-projection.md.
type UserProjection struct {
	Name         string              `yaml:"name"`
	MaxClaimsAge Duration            `yaml:"max_claims_age"`
	MaxTags      int                 `yaml:"max_tags"`
	Tags         []ProjectionTagRule `yaml:"tags"`
	compiled     *compiledProjection
}

// ProjectionTagRule maps verified claims to one set of lowercase tag values.
type ProjectionTagRule struct {
	Key       string `yaml:"key"`
	Values    string `yaml:"values"`
	MinValues int    `yaml:"min_values"`
	MaxValues int    `yaml:"max_values"`
}

type compiledProjection struct {
	name  *vm.Program
	tags  []*vm.Program
	reads map[string]bool
}

// VerifiedIdentity contains only verified claims and server-vouched facts.
// Registered ID-token claims must be restored from the verified token after mapping.
type VerifiedIdentity struct {
	IDToken    map[string]interface{}
	UserInfo   map[string]interface{}
	IDP        map[string]interface{}
	Connection map[string]interface{}
	Server     map[string]interface{}
	IssuedAt   time.Time
	VerifiedAt time.Time
}

// NatsUser is the complete projection result. No partial result is returned.
type NatsUser struct {
	Name       string
	Tags       map[string][]string
	FreshUntil time.Time
}

// ProjectionError has bounded, non-sensitive fields safe to log by default.
// Claim values and expression evaluator messages are deliberately excluded.
type ProjectionError struct {
	Kind   string
	Output string
}

func (e *ProjectionError) Error() string { return "user projection: " + e.Kind + " (" + e.Output + ")" }

func projectionError(kind, output string) error { return &ProjectionError{Kind: kind, Output: output} }

func validProjectionToken(value string, lower bool) bool {
	if len(value) == 0 || len(value) > projectionMaxTokenBytes {
		return false
	}
	for _, c := range []byte(value) {
		if c < '!' || c > '~' || strings.ContainsRune(".*>{}", rune(c)) {
			return false
		}
	}
	return !lower || value == strings.ToLower(value)
}

func (r *UserProjection) compile(multipleIDPs bool) error {
	if r.MaxClaimsAge.Duration <= 0 {
		return fmt.Errorf("user_projection.max_claims_age must be positive")
	}
	if r.MaxTags == 0 {
		r.MaxTags = projectionDefaultMaxTags
	}
	if r.MaxTags < 1 || r.MaxTags > projectionMaxTags || len(r.Tags) > r.MaxTags {
		return fmt.Errorf("user_projection.max_tags must be between 1 and %d and bound rule count", projectionMaxTags)
	}
	compiled := &compiledProjection{reads: map[string]bool{}}
	name, err := compileProjectionExpr(r.Name, compiled.reads)
	if err != nil {
		return fmt.Errorf("user_projection.name: %w", err)
	}
	// Parse-normalized forms prevent expressions which mention sub but discard it.
	tree, err := parser.Parse(r.Name)
	if err != nil {
		return err
	}
	form := tree.Node.String()
	single := form == "id_token.sub" || form == "digest(id_token.sub)"
	multi := form == `idp.key + ":" + id_token.sub` || form == `digest(idp.key + ":" + id_token.sub)`
	if !multi && (!single || multipleIDPs) {
		return fmt.Errorf("user_projection.name must preserve id_token.sub and, with multiple IdPs, prefix idp.key (optionally digest the result)")
	}
	compiled.name = name
	seen := map[string]bool{}
	for _, rule := range r.Tags {
		if !validProjectionToken(rule.Key, true) || strings.Contains(rule.Key, ":") || seen[rule.Key] {
			return fmt.Errorf("user_projection tag keys must be unique lowercase tokens without ':'")
		}
		seen[rule.Key] = true
		if rule.MinValues < 0 || rule.MaxValues < 0 || (rule.MaxValues > 0 && rule.MinValues > rule.MaxValues) || rule.MinValues > r.MaxTags || rule.MaxValues > r.MaxTags {
			return fmt.Errorf("invalid user_projection tag cardinality")
		}
		program, err := compileProjectionExpr(rule.Values, compiled.reads)
		if err != nil {
			return fmt.Errorf("user_projection.tags.%s: %w", rule.Key, err)
		}
		compiled.tags = append(compiled.tags, program)
	}
	r.compiled = compiled
	return nil
}

type projectionSyntax struct {
	reads map[string]bool
	err   error
}

func (v *projectionSyntax) Visit(node *ast.Node) {
	if v.err != nil {
		return
	}
	switch n := (*node).(type) {
	case *ast.IdentifierNode:
		switch n.Value {
		case "id_token", "userinfo", "idp", "connection", "server":
			v.reads[n.Value] = true
		case "capture", "digest":
		default:
			v.err = fmt.Errorf("unknown projection identifier %q", n.Value)
		}
	case *ast.MemberNode:
		if _, ok := n.Property.(*ast.StringNode); !ok {
			v.err = fmt.Errorf("projection member access must use literal keys")
		}
	case *ast.CallNode:
		id, ok := n.Callee.(*ast.IdentifierNode)
		if !ok {
			v.err = fmt.Errorf("projection method calls are not allowed")
			return
		}
		switch id.Value {
		case "digest":
			if len(n.Arguments) != 1 {
				v.err = fmt.Errorf("digest requires one argument")
			}
		case "capture":
			if len(n.Arguments) != 2 {
				v.err = fmt.Errorf("capture requires two arguments")
				return
			}
			pattern, ok := n.Arguments[1].(*ast.StringNode)
			if !ok {
				v.err = fmt.Errorf("capture pattern must be a literal")
				return
			}
			_, v.err = projectionPattern(pattern.Value)
		default:
			v.err = fmt.Errorf("projection allows only capture and digest calls")
		}
	case *ast.BinaryNode:
		switch n.Operator {
		case "+", "==", "!=", "<", "<=", ">", ">=", "and", "or", "&&", "||", "in", "not in", "??":
		default:
			v.err = fmt.Errorf("unsupported projection operator %q", n.Operator)
		}
	case *ast.UnaryNode:
		if n.Operator != "!" && n.Operator != "not" {
			v.err = fmt.Errorf("unsupported projection unary operator")
		}
	case *ast.StringNode, *ast.IntegerNode, *ast.BoolNode, *ast.NilNode, *ast.ArrayNode, *ast.ConditionalNode, *ast.ChainNode:
	default:
		v.err = fmt.Errorf("unsupported projection expression construct %T", n)
	}
}

func projectionPattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > projectionMaxPatternBytes {
		return nil, fmt.Errorf("capture pattern too long")
	}
	re, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
	if err != nil {
		return nil, err
	}
	if re.NumSubexp() != 1 {
		return nil, fmt.Errorf("capture pattern must contain exactly one capture group")
	}
	return re, nil
}

func compileProjectionExpr(source string, reads map[string]bool) (*vm.Program, error) {
	if len(source) == 0 || len(source) > projectionMaxExpressionBytes {
		return nil, fmt.Errorf("expression must contain 1 to %d bytes", projectionMaxExpressionBytes)
	}
	config := conf.CreateNew()
	config.MaxNodes = projectionMaxNodes
	tree, err := parser.ParseWithConfig(source, config)
	if err != nil {
		return nil, err
	}
	syntax := &projectionSyntax{reads: reads}
	ast.Walk(&tree.Node, syntax)
	if syntax.err != nil {
		return nil, syntax.err
	}
	// Only pure functions are installed. No config-rendering IO functions or builtins.
	env := projectionEnvironment(VerifiedIdentity{})
	return expr.Compile(source, expr.Env(env), expr.DisableAllBuiltins(), expr.MaxNodes(projectionMaxNodes), expr.Optimize(false))
}

func projectionStrings(value interface{}) ([]string, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{value}, nil
	case []string:
		return value, nil
	case []interface{}:
		values := make([]string, 0, len(value))
		for _, v := range value {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("expected strings")
			}
			values = append(values, s)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("expected string or list of strings")
	}
}

func projectionCapture(value interface{}, pattern string) ([]string, error) {
	re, err := projectionPattern(pattern)
	if err != nil {
		return nil, err
	}
	values, err := projectionStrings(value)
	if err != nil {
		return nil, err
	}
	matches := []string{}
	for _, value := range values {
		if m := re.FindStringSubmatch(value); m != nil {
			matches = append(matches, m[1])
		}
	}
	return matches, nil
}

func projectionEnvironment(identity VerifiedIdentity) map[string]interface{} {
	return map[string]interface{}{
		"id_token": identity.IDToken, "userinfo": identity.UserInfo, "idp": identity.IDP,
		"connection": identity.Connection, "server": identity.Server,
		"capture": projectionCapture, "digest": sha256Hex,
	}
}

// Project is pure: all timestamps, claims and facts are supplied by its caller.
// Rules must have been compiled as part of configuration loading.
func (r *UserProjection) Project(identity VerifiedIdentity) (*NatsUser, error) {
	if r.compiled == nil {
		return nil, projectionError("Evaluation", "configuration")
	}
	// Bound actual input independently of the expression VM's allocation budget.
	data, err := json.Marshal([]interface{}{identity.IDToken, identity.UserInfo, identity.IDP, identity.Connection, identity.Server})
	if err != nil || len(data) > projectionMaxInputBytes {
		return nil, projectionError("TooMany", "identity")
	}
	if identity.VerifiedAt.IsZero() || identity.IssuedAt.IsZero() {
		return nil, projectionError("Missing", "timestamp")
	}
	if r.compiled.reads["userinfo"] && identity.UserInfo == nil {
		return nil, projectionError("Unavailable", "userinfo")
	}
	user := &NatsUser{Tags: map[string][]string{}, FreshUntil: identity.VerifiedAt.Add(r.MaxClaimsAge.Duration)}
	// Config facts have no age. ID-token facts retain the signed token's iat.
	if r.compiled.reads["id_token"] {
		if identity.IssuedAt.After(identity.VerifiedAt) {
			return nil, projectionError("Stale", "id_token")
		}
		until := identity.IssuedAt.Add(r.MaxClaimsAge.Duration)
		if !until.After(identity.VerifiedAt) {
			return nil, projectionError("Stale", "id_token")
		}
		if until.Before(user.FreshUntil) {
			user.FreshUntil = until
		}
	}
	env := projectionEnvironment(identity)
	eval := func(program *vm.Program, output string) (interface{}, error) {
		machine := vm.VM{MemoryBudget: projectionMemoryBudget}
		value, err := machine.Run(program, env)
		if err != nil {
			return nil, projectionError("Evaluation", output)
		}
		return value, nil
	}
	value, err := eval(r.compiled.name, "name")
	if err != nil {
		return nil, err
	}

	// Even a digest or a provider prefix must not turn an absent subject into a
	// shared, apparently valid identity.
	subject, subjectIsString := identity.IDToken["sub"].(string)
	if !subjectIsString {
		return nil, projectionError("WrongType", "name")
	}
	if subject == "" {
		return nil, projectionError("Missing", "name")
	}
	name, ok := value.(string)
	if !ok {
		return nil, projectionError("WrongType", "name")
	}
	if name == "" {
		return nil, projectionError("Missing", "name")
	}
	if !validProjectionToken(name, false) {
		return nil, projectionError("NotAToken", "name")
	}
	user.Name = name
	total := 0
	for i, rule := range r.Tags {
		value, err := eval(r.compiled.tags[i], rule.Key)
		if err != nil {
			return nil, err
		}
		values, err := projectionStrings(value)
		if err != nil {
			return nil, projectionError("WrongType", rule.Key)
		}
		unique := map[string]bool{}
		for _, v := range values {
			if !validProjectionToken(v, true) {
				return nil, projectionError("NotAToken", rule.Key)
			}
			unique[v] = true
		}
		count := len(unique)
		if count < rule.MinValues {
			return nil, projectionError("Missing", rule.Key)
		}
		if rule.MaxValues > 0 && count > rule.MaxValues {
			return nil, projectionError("TooMany", rule.Key)
		}
		total += count
		if total > r.MaxTags {
			return nil, projectionError("TooMany", "tags")
		}
		sorted := make([]string, 0, count)
		for v := range unique {
			sorted = append(sorted, v)
		}
		sort.Strings(sorted)
		user.Tags[rule.Key] = sorted
	}
	return user, nil
}

func (u *NatsUser) mapping() map[string]interface{} {
	return map[string]interface{}{"name": u.Name, "tags": u.Tags, "fresh_until": u.FreshUntil}
}

func (u *NatsUser) jwtTags() []string {
	keys := make([]string, 0, len(u.Tags))
	for key := range u.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	tags := []string{}
	for _, key := range keys {
		for _, value := range u.Tags[key] {
			tags = append(tags, key+":"+value)
		}
	}
	return tags
}
