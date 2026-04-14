package authn

import (
	"os"
	"slices"
)

var systemMembers = []string{}

func init() {
	alisOsProjectEnv := os.Getenv("ALIS_OS_PROJECT")
	if alisOsProjectEnv != "" {
		environmentServiceAccountEmail := "alis-build@" + alisOsProjectEnv + ".iam.gserviceaccount.com"
		systemMembers = append(systemMembers, "serviceAccount:"+environmentServiceAccountEmail)
	}
}

func AddSystemMembers(members ...string) {
	systemMembers = append(systemMembers, members...)
}

func (i *Identity) IsSystem() bool {
	return slices.Contains(systemMembers, i.PolicyMember())
}
