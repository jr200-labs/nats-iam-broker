package broker

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

func FuzzProjectionSafety(f *testing.F) {
	for _, seed := range []struct {
		sub, table, role string
		age              int64
	}{
		{"alice", "menu_prices", "waiter", 0}, {"bob", "staff_rotas", "head_chef", 899},
		{">", "menu_prices", "waiter", 0}, {"{{tag(role)}}", "menu_prices", "waiter", 0},
		{"alice", "menu.prices", "waiter", 0}, {"alice", "menu_prices", "WAITER", 0},
		{"аlice", "menu_prices", "waiter", 0}, {"alice", "menu_prices", "waiter", 900},
	} {
		f.Add(seed.sub, seed.table, seed.role, seed.age)
	}
	rules := &UserProjection{Name: "id_token.sub", MaxClaimsAge: Duration{15 * time.Minute}, Tags: []ProjectionTagRule{
		{Key: "write", Values: "userinfo.tables"}, {Key: "role", Values: "userinfo.roles"},
	}}
	if err := rules.compile(false); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, sub, table, role string, age int64) {
		now := time.Unix(1800000000, 0)
		// Keep generated timestamps in a meaningful range without duration overflow.
		age = age % 3600
		identity := VerifiedIdentity{IDToken: map[string]interface{}{"sub": sub}, UserInfo: map[string]interface{}{
			"tables": []string{table, table}, "roles": []string{role, role},
		}, VerifiedAt: now, IssuedAt: now.Add(-time.Duration(age) * time.Second)}
		user, err := rules.Project(identity)
		if err != nil {
			if user != nil {
				t.Fatal("refusal returned partial user")
			}
			return
		}
		again, err := rules.Project(identity)
		if err != nil || !reflect.DeepEqual(user, again) {
			t.Fatal("projection is not deterministic")
		}
		if user.Name != sub {
			t.Fatal("name no longer preserves signed identity")
		}
		if !user.FreshUntil.After(now) || user.FreshUntil.After(identity.IssuedAt.Add(15*time.Minute)) {
			t.Fatal("invalid freshness interval")
		}
		for _, token := range []string{user.Name, user.Tags["write"][0], user.Tags["role"][0]} {
			subject := "cmd." + token + ".tail"
			if !natsserver.IsValidLiteralSubject(subject) || len(strings.Split(subject, ".")) != 3 || strings.ContainsAny(token, "{}") {
				t.Fatalf("unsafe projected token %q", token)
			}
		}
		tags := user.jwtTags()
		if len(tags) != 2 || tags[0] != "role:"+role || tags[1] != "write:"+table || strings.ToLower(tags[0]) != tags[0] || strings.ToLower(tags[1]) != tags[1] {
			t.Fatal("tag ordering, deduplication or case contract changed")
		}
	})
}

func BenchmarkProjectionMaximumInput(b *testing.B) {
	rules := &UserProjection{Name: "id_token.sub", MaxClaimsAge: Duration{15 * time.Minute}, Tags: []ProjectionTagRule{
		{Key: "write", Values: `capture(userinfo.groups, "^write:([a-z0-9_]+)$")`},
	}}
	if err := rules.compile(false); err != nil {
		b.Fatal(err)
	}
	groups := make([]string, 3000)
	for i := range groups {
		groups[i] = "write:menu_prices"
	}
	now := time.Unix(1800000000, 0)
	identity := VerifiedIdentity{IDToken: map[string]interface{}{"sub": "alice"}, UserInfo: map[string]interface{}{"groups": groups}, IssuedAt: now, VerifiedAt: now}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rules.Project(identity); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProjectionAggregateWorkRefusal(b *testing.B) {
	rules := &UserProjection{Name: "id_token.sub", MaxClaimsAge: Duration{15 * time.Minute}}
	for i := 0; i < 128; i++ {
		rules.Tags = append(rules.Tags, ProjectionTagRule{Key: fmt.Sprintf("grant%d", i), Values: `capture(userinfo.groups, "^write:([a-z0-9_]+)$")`})
	}
	if err := rules.compile(false); err != nil {
		b.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	identity := VerifiedIdentity{IDToken: map[string]interface{}{"sub": "alice"}, UserInfo: map[string]interface{}{"padding": strings.Repeat("x", 60000)}, IssuedAt: now, VerifiedAt: now}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rules.Project(identity)
		var refusal *ProjectionError
		if !errors.As(err, &refusal) || refusal.Output != "work" {
			b.Fatalf("expected work refusal, got %v", err)
		}
	}
}
