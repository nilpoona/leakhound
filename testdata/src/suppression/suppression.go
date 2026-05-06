package main

import (
	"log/slog"
)

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

// --- Suppressed: no diagnostic expected ---

func testSuppressedStructByRuleID() {
	u := User{Password: "secret"}
	slog.Info("user", u) //noleak:LH0003
}

func testSuppressedFieldByRuleID() {
	u := User{Password: "secret"}
	slog.Info("user", u.Password) //noleak:LH0004
}

func testSuppressedByAll() {
	u := User{Password: "secret"}
	slog.Info("user", u) //noleak:all
}

func testSuppressedWithTrailingText() {
	u := User{Password: "secret"}
	slog.Info("user", u) //noleak:LH0003 intentionally safe: MaskedUser applied upstream
}

func testSuppressedPrecedingLine() {
	u := User{Password: "secret"}
	//noleak:LH0003
	slog.Info("user", u)
}

func testSuppressedPrecedingLineAll() {
	u := User{Password: "secret"}
	//noleak:all
	slog.Info("user", u.Password)
}

// --- Not suppressed: diagnostics expected ---

func testStructNotSuppressed() {
	u := User{Password: "secret"}
	slog.Info("user", u) // want `struct 'User' contains sensitive fields`
}

func testFieldNotSuppressed() {
	u := User{Password: "secret"}
	slog.Info("user", u.Password) // want `sensitive field 'User.Password'`
}

func testWrongRuleIDNotSuppressed() {
	u := User{Password: "secret"}
	// LH0003 suppresses struct-logging; direct field access (LH0004) still fires
	slog.Info("user", u.Password) // want `sensitive field 'User.Password'`
}

func testTwoLinesAboveNotSuppressed() {
	//noleak:LH0003
	u := User{Password: "secret"}
	slog.Info("user", u) // want `struct 'User' contains sensitive fields`
}

func main() {}
