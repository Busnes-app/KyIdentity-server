package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestWideTrustedProxyWarnings(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		warn bool
	}{
		{"0.0.0.0/0", true}, {"::/0", true},
		{"10.0.0.0/7", true}, {"172.16.0.0/11", true},
		{"192.168.0.0/15", true}, {"fc00::/6", true},
		{"10.0.0.0/8", false}, {"172.16.0.0/12", false},
		{"192.168.0.0/16", false}, {"fc00::/7", false},
		{"10.89.0.10/32", false}, {"fd00::1/128", false},
		{"203.0.113.7/32", false}, {"203.0.113.0/24", false},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			var logs []string
			warnWideTrustedProxies([]string{tc.cidr}, func(f string, args ...any) {
				logs = append(logs, fmt.Sprintf(f, args...))
			})
			if (len(logs) == 1) != tc.warn {
				t.Fatalf("warnings = %v, want warning %v", logs, tc.warn)
			}
			if tc.warn {
				for _, want := range []string{tc.cidr, "exact address", "tunnel alone", "forged client addresses"} {
					if !strings.Contains(logs[0], want) {
						t.Errorf("warning %q missing %q", logs[0], want)
					}
				}
			}
		})
	}
}
