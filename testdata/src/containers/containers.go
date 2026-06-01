package main

import "log/slog"

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

type Safe struct {
	Name string
	ID   int
}

// Users is a named slice type over a sensitive element type.
type Users []User

// Logging a container whose element / key / value is a struct with sensitive
// fields is detected: the container is unwrapped down to the element type.

func logSlice(users []User) {
	slog.Info("users", "list", users) // want `logged value contains type 'User' with sensitive fields`
}

func logArray(users [3]User) {
	slog.Info("users", "arr", users) // want `logged value contains type 'User' with sensitive fields`
}

func logMapValue(m map[string]User) {
	slog.Info("users", "m", m) // want `logged value contains type 'User' with sensitive fields`
}

func logMapKey(m map[User]int) {
	slog.Info("users", "m", m) // want `logged value contains type 'User' with sensitive fields`
}

func logNamedSlice(users Users) {
	slog.Info("users", "u", users) // want `logged value contains type 'User' with sensitive fields`
}

func logPointerSlice(users []*User) {
	slog.Info("users", "u", users) // want `logged value contains type 'User' with sensitive fields`
}

func logNestedContainer(m map[string][]User) {
	slog.Info("users", "m", m) // want `logged value contains type 'User' with sensitive fields`
}

// Direct field access through a container index/range IS detected as a field
// access (LH0004), distinct from the whole-container case above.

func logSliceIndexField(users []User) {
	slog.Info("u", "pw", users[0].Password) // want `sensitive field 'User.Password' should not be logged`
}

func logRangeField(users []User) {
	for _, u := range users {
		slog.Info("u", "pw", u.Password) // want `sensitive field 'User.Password' should not be logged`
	}
}

// Containers of non-sensitive element types must NOT be flagged.

func safeSlice(s []Safe) {
	slog.Info("s", "list", s)
}

func safeMap(m map[string]Safe) {
	slog.Info("s", "m", m)
}

func safeStringSlice(s []string) {
	slog.Info("s", "list", s)
}

func main() {}
