package models

// User struct with sensitive fields in a separate package
type User struct {
	Name     string
	Email    string
	Password string `sensitive:"true"`
	APIToken string `sensitive:"true"`
}

// SafeStruct without sensitive fields
type SafeStruct struct {
	PublicData string
	ID         int
}
