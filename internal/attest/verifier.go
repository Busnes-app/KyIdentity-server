package attest

import "time"

// Verifier binds Verify to this deployment's app identity and policy.
type Verifier struct {
	roots         Roots
	status        Status
	appPackage    string
	digests       [][]byte
	requireLocked func() bool
}

func NewVerifier(roots Roots, status Status, appPackage string, digests [][]byte, requireLocked func() bool) *Verifier {
	return &Verifier{roots, status, appPackage, digests, requireLocked}
}

func (v *Verifier) Verify(chain [][]byte, want Expectation) Result {
	want.AppPackage, want.AppDigests, want.RequireLockedBootloader = v.appPackage, v.digests, v.requireLocked()
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	return Verify(chain, want, v.roots, v.status)
}
