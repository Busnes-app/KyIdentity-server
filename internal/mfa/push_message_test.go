package mfa

import "testing"

func TestPushResponseMessageGoldenVectors(t *testing.T) {
	b := PushBinding{Origin: "https://id.example.com", UserID: "u-123", DeviceID: "d-456", ChallengeID: "c-789", Purpose: "login", ExpiresAtMS: 1791331200000}
	got, err := PushResponseMessage(b, true, "42")
	if err != nil || string(got) != "kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42" {
		t.Fatalf("approve = %q, %v", got, err)
	}
	b.Purpose = "step_up"
	got, err = PushResponseMessage(b, false, "")
	if err != nil || string(got) != "kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|" {
		t.Fatalf("deny = %q, %v", got, err)
	}
}

func TestPushResponseMessageRefusesAmbiguousFields(t *testing.T) {
	ok := PushBinding{Origin: "https://id.example.com", UserID: "u", DeviceID: "d", ChallengeID: "c", Purpose: "login", ExpiresAtMS: 1}
	bad := []PushBinding{}
	for _, mutate := range []func(*PushBinding){
		func(b *PushBinding) { b.UserID = "u|x" },
		func(b *PushBinding) { b.DeviceID = "" },
		func(b *PushBinding) { b.ChallengeID = "" },
		func(b *PushBinding) { b.Origin = "" },
		func(b *PushBinding) { b.Purpose = "session" },
	} {
		b := ok
		mutate(&b)
		bad = append(bad, b)
	}
	for _, b := range bad {
		if _, err := PushResponseMessage(b, true, "42"); err == nil {
			t.Fatalf("accepted %+v", b)
		}
	}
	if _, err := PushResponseMessage(ok, true, "4|2"); err == nil {
		t.Fatal("accepted digits with a separator")
	}
}

func TestIssuerOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://ID.Example.com/":                "https://id.example.com",
		"https://id.example.com:443":             "https://id.example.com",
		"https://id.example.com:8443/kyidentity": "https://id.example.com:8443",
		"http://127.0.0.1:8080":                  "http://127.0.0.1:8080",
		"https://[::1]":                          "https://[::1]",
		"https://[::1]:443":                      "https://[::1]",
		"https://[::1]:8443/x":                   "https://[::1]:8443",
	} {
		if got, err := IssuerOrigin(in); err != nil || got != want {
			t.Errorf("IssuerOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := IssuerOrigin("not a url"); err == nil {
		t.Error("accepted a non-URL")
	}
}
