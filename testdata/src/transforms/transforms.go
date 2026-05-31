package main

import (
	"fmt"
	"log/slog"
	"strings"
)

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

// These cases document a KNOWN LIMITATION: taint is not propagated through
// transformation functions (fmt.Sprintf, strings.ToUpper, etc.). The return
// value of such a call is treated as clean even when a sensitive field flowed
// in. They are written with no expectation comment so the test asserts "no
// diagnostic" today and trips if data flow through stdlib transforms is ever
// added.

func throughSprintf(u User) {
	s := fmt.Sprintf("%s", u.Password)
	slog.Info("x", "s", s) // not detected: taint lost through Sprintf
}

func throughToUpper(u User) {
	s := strings.ToUpper(u.Password)
	slog.Info("x", "s", s) // not detected: taint lost through strings.ToUpper
}

func throughConcat(u User) {
	s := "pw=" + u.Password
	slog.Info("x", "s", s) // not detected: taint lost through string concat
}

// Counter-positive: passing the sensitive field DIRECTLY (no transform) is
// still detected, proving the gap above is specific to the transform, not the
// surrounding code.
func directNoTransform(u User) {
	slog.Info("x", "pw", u.Password) // want `sensitive field 'User.Password' should not be logged`
}

func main() {}
