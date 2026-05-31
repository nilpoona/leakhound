package main

import "log/slog"

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

// reassignedToSafe documents the flow-INSENSITIVE behavior noted in the
// "Known Limitations" section of CLAUDE.md: once a variable is tainted by a
// sensitive field, a later reassignment to a safe literal does NOT clear the
// taint, so the log call is still flagged. This is a (currently accepted)
// false positive; the expectation comment pins the behavior so a future
// flow-sensitive implementation visibly changes this test.
func reassignedToSafe(u User) {
	p := u.Password
	p = "redacted"
	slog.Info("x", "p", p) // want `variable "p" contains sensitive field "User.Password"`
}

// shadowedInBranch confirms a same-named variable that is only ever assigned
// a safe value is not flagged.
func shadowedSafe(u User) {
	p := u.Name
	slog.Info("x", "p", p) // safe: Name is not sensitive
}

// reverseOrder taints a variable AFTER an earlier safe assignment with the
// same name in a sibling scope. The sensitive one is never logged.
func siblingScopes(u User) {
	{
		name := u.Name
		slog.Info("x", "n", name) // safe
	}
	{
		secret := u.Password
		_ = secret // not logged
	}
}

func main() {}
