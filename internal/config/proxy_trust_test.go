package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsWideMultiHopProxyTrust(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "172.16.0.0/11", "192.168.0.0/15", "fc00::/6", "::ffff:0.0.0.0/96", "::ffff:192.168.0.0/111", "10.89.0.10/32,::/0"} {
		for _, header := range []string{"", "X-Forwarded-For", "x-FoRwArDeD-fOr", " Forwarded "} {
			t.Run(cidr+"/"+header, func(t *testing.T) {
				t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
				t.Setenv("TRUSTED_PROXY_CIDRS", cidr)
				t.Setenv("KYIDENTITY_FORWARDED_HEADER", header)
				cfg, err := Load()
				if err == nil || cfg != nil {
					t.Fatal("unsafe trust accepted")
				}
				for _, want := range []string{"TRUSTED_PROXY_CIDRS", "KYIDENTITY_FORWARDED_HEADER", "CF-Connecting-IP", "overwrite", "only"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("unactionable refusal: %v", err)
					}
				}
			})
		}
	}
}

func TestLoadPreservesNarrowAndSingleIPProxyTrust(t *testing.T) {
	for _, cidr := range []string{"", "10.89.0.10", "fd00::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "203.0.113.7/32", "203.0.113.0/24", "::ffff:10.0.0.0/104", "::ffff:203.0.113.7/128", "10.89.0.10/32,fd00::1/128"} {
		t.Run(cidr, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("TRUSTED_PROXY_CIDRS", cidr)
			t.Setenv("KYIDENTITY_FORWARDED_HEADER", "")
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, header := range []string{"CF-Connecting-IP", "cf-connecting-ip", " X-Real-IP "} {
		t.Run(header, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("TRUSTED_PROXY_CIDRS", "0.0.0.0/0,::/0")
			t.Setenv("KYIDENTITY_FORWARDED_HEADER", header)
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
