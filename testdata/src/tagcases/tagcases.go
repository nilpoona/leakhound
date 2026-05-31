package main

import "log/slog"

// User exercises struct-tag edge cases for the sensitive marker.
type User struct {
	Name string

	// Password is the baseline positive: a plain sensitive tag.
	Password string `sensitive:"true"`

	// NotSecret carries sensitive:"false". HasSensitiveTag only matches the
	// literal sensitive:"true", so this field must NOT be treated as sensitive.
	NotSecret string `sensitive:"false"`

	// Token combines another struct tag with the sensitive marker, and places
	// the marker second. Tag-order / co-tenancy must not break detection.
	Token string `json:"token" sensitive:"true"`

	// PwPtr is a pointer-typed sensitive field. Direct access to a pointer
	// field is still a leak.
	PwPtr *string `sensitive:"true"`
}

// AliasUser is a package-level type alias for User.
//
// Known limitation: field access through a type alias is currently NOT
// detected because field lookup keys on the alias name rather than the
// underlying type. This case is kept with no expectation comment so the test
// fails (unexpected diagnostic) the day alias resolution is implemented — a
// deliberate tripwire for that future improvement.
type AliasUser = User

func baseline(u User) {
	slog.Info("x", "pw", u.Password) // want `sensitive field 'User.Password' should not be logged`
}

func falseTagNotFlagged(u User) {
	// sensitive:"false" must NOT be detected.
	slog.Info("x", "n", u.NotSecret)
}

func combinedTag(u User) {
	slog.Info("x", "t", u.Token) // want `sensitive field 'User.Token' should not be logged`
}

func pointerField(u User) {
	slog.Info("x", "pw", u.PwPtr) // want `sensitive field 'User.PwPtr' should not be logged`
}

func aliasFieldAccess(a AliasUser) {
	// Known gap (see AliasUser doc): currently NOT detected.
	slog.Info("a", "pw", a.Password)
}

func main() {}
