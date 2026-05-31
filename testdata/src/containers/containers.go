package main

import "log/slog"

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

// These cases document a KNOWN LIMITATION: leakhound does not look inside
// container types (slice / array / map) for element structs carrying
// sensitive fields. Logging the container whole is therefore NOT detected.
//
// They are intentionally written with no expectation comments so the test
// asserts "no diagnostic" today, and will start failing (unexpected
// diagnostic) the day container element inspection is implemented — a
// tripwire that forces this file to be revisited.

func logSlice(users []User) {
	slog.Info("users", "list", users) // not detected: slice element is sensitive
}

func logArray(users [3]User) {
	slog.Info("users", "arr", users) // not detected: array element is sensitive
}

func logMapValue(m map[string]User) {
	slog.Info("users", "m", m) // not detected: map value is sensitive
}

func logMapKey(m map[User]int) {
	slog.Info("users", "m", m) // not detected: map key is sensitive
}

// Direct field access through a container index/range IS detected (the leak is
// the field access itself, not the container), so these carry an expectation.

func logSliceIndexField(users []User) {
	slog.Info("u", "pw", users[0].Password) // want `sensitive field 'User.Password' should not be logged`
}

func logRangeField(users []User) {
	for _, u := range users {
		slog.Info("u", "pw", u.Password) // want `sensitive field 'User.Password' should not be logged`
	}
}

func main() {}
