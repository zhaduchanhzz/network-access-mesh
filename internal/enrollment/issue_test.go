package enrollment

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/headscale"
	"github.com/zhaduchanhzz/network-access-mesh/internal/store/sqlcdb"
)

// TestIssuedKey: the key Headscale lists under a request's key id is the request's only when the reusable flag, the
// expiry and the owner fit what the issuance recorded (a restore of an older snapshot hands ids out again — §6.3).
func TestIssuedKey(t *testing.T) {
	mine, theirs := uuid.New(), uuid.New()
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Millisecond)
	owned := sqlcdb.EnrollmentRequest{TargetMembershipID: &mine, CredentialExpiresAt: &exp}
	reusable := owned
	reusable.Reusable = true
	tagOnly := sqlcdb.EnrollmentRequest{Reusable: true, CredentialExpiresAt: &exp}
	user := func(name string) *headscale.User { return &headscale.User{ID: 7, Name: name} }
	key := func(reusable bool, expiry time.Time, u *headscale.User) headscale.PreAuthKey {
		return headscale.PreAuthKey{ID: 3, Reusable: reusable, Expiration: expiry, User: u}
	}
	for _, c := range []struct {
		name string
		r    sqlcdb.EnrollmentRequest
		k    headscale.PreAuthKey
		want bool
	}{
		{"as issued", owned, key(false, exp, user(memberUserPrefix+mine.String())), true},
		{"expired since (expired by the platform while still valid: earlier)", owned, key(false, time.Now().Add(-time.Minute), user(memberUserPrefix+mine.String())), true},
		{"Headscale's rounding of the expiry", owned, key(false, exp.Add(500*time.Millisecond), user(memberUserPrefix+mine.String())), true},
		{"single-use request, reusable key", owned, key(true, exp, user(memberUserPrefix+mine.String())), false},
		{"reusable request, single-use key", reusable, key(false, exp, user(memberUserPrefix+mine.String())), false},
		{"lives later than the credential", owned, key(false, exp.Add(2*time.Second), user(memberUserPrefix+mine.String())), false},
		{"key of another member", owned, key(false, exp, user(memberUserPrefix+theirs.String())), false},
		{"tag-only request, key of a member", tagOnly, key(true, exp, user(memberUserPrefix+mine.String())), false},
		{"tag-only request, no owner", tagOnly, key(true, exp, nil), true},
		{"tag-only request, owner reported outside mg-", tagOnly, key(true, exp, user("tagged-devices")), true},
	} {
		if got := issuedKey(c.r, c.k); got != c.want {
			t.Errorf("%s: issuedKey = %v, want %v", c.name, got, c.want)
		}
	}
}
