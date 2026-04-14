# Authentication

This module provides three main packages:

- `auth` provides an `Identity` which is shared by the `authn` and `authz` packages.
- `authn` provides a client for authenticating users.
- `authz` provides a package for authorizing users.

In addition, it provides a `policypool` package which simplifies fetching IAM
policies concurrently from various sources.
