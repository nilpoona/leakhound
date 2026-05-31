package app

import (
	"log/slog"

	"example.com/crosspkgflow/secret"
)

// LeakViaCrossPkgReturn logs the result of a cross-package function whose
// return value is derived from a sensitive field. Expected: LH0005 at the
// position of the GetPassword call.
func LeakViaCrossPkgReturn(u secret.User) {
	slog.Info("msg", "pw", secret.GetPassword(u)) // want "cross-package function call returns sensitive field"
}

// LeakViaCrossPkgSink passes a sensitive value into a cross-package function
// whose body forwards the parameter to a logger. Expected: LH0006 at the
// position of the sensitive argument.
func LeakViaCrossPkgSink(u secret.User) {
	secret.LogIt(u.Password) // want "passed to cross-package function .LogIt. whose parameter"
}

// LeakViaIndirectSink exercises transitive sink propagation across packages:
// secret.Indirect calls secret.LogIt internally, so Indirect's parameter
// must also be marked as a sink. Expected: LH0006 at the argument.
func LeakViaIndirectSink(u secret.User) {
	secret.Indirect(u.Password) // want "passed to cross-package function .Indirect. whose parameter"
}

// LeakViaCrossPkgMultiReturn logs position 0 of a cross-package multi-value
// return derived from a sensitive field. The taint is tracked across the
// package boundary and surfaces at the logged variable.
func LeakViaCrossPkgMultiReturn(u secret.User) {
	pw, err := secret.GetPasswordAndErr(u)
	_ = err
	slog.Info("msg", "pw", pw) // want "contains sensitive field"
}

// SafeCrossPkgMultiReturnErr logs only position 1 (the error) — must NOT be
// flagged.
func SafeCrossPkgMultiReturnErr(u secret.User) {
	_, err := secret.GetPasswordAndErr(u)
	slog.Info("msg", "err", err)
}

// LeakViaDeepSink passes a sensitive value into a cross-package function whose
// parameter only reaches a logger after THREE more hops. Expected: LH0006 at
// the argument.
func LeakViaDeepSink(u secret.User) {
	secret.DeepSink(u.Password) // want "passed to cross-package function .DeepSink. whose parameter"
}

// SafeCrossPkgCall passes a non-sensitive field across packages — must NOT
// be flagged.
func SafeCrossPkgCall(u secret.User) {
	secret.LogIt(u.Name)
}
