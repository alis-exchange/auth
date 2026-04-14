package auth

import (
	"os"
)

var systemEmails = []string{}

func init() {
	alisOsProjectEnv := os.Getenv("ALIS_OS_PROJECT")
	if alisOsProjectEnv != "" {
		environmentServiceAccountEmail := "alis-build@" + alisOsProjectEnv + ".iam.gserviceaccount.com"
		systemEmails = append(systemEmails, environmentServiceAccountEmail)
	}
}

func AddSystemEmail(email string) {
	systemEmails = append(systemEmails, email)
}

func (i *Identity) IsSystem() bool {
	return i.Type == System
}

var SystemIdentity = &Identity{
	Type: System,
	ID:   "system",
}
