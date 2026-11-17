package identity

// The fake OpenID Provider lives in internal/identity/identitytest so that the tests of other packages (the API
// composition test of internal/httpapi/authzhook) can drive a login too; these aliases keep the names the tests of
// this package use (identity.NewFakeIdP, identity.FakeUser, …).

import "github.com/zhaduchanhzz/network-access-mesh/internal/identity/identitytest"

type (
	// FakeIdP is identitytest.FakeIdP.
	FakeIdP = identitytest.FakeIdP
	// FakeUser is identitytest.FakeUser.
	FakeUser = identitytest.FakeUser
)

var (
	NewFakeIdP  = identitytest.NewFakeIdP
	JWK         = identitytest.JWK
	SignRS256   = identitytest.SignRS256
	SignHS256   = identitytest.SignHS256
	UnsignedJWT = identitytest.UnsignedJWT
)
