package store

import "strings"

// MaxForwardPath bounds a path (and query) the browser is sent back to.
const MaxForwardPath = 2048

// ForwardPath accepts an origin-relative path (and query) the browser may be sent back to.
func ForwardPath(p string) bool {
	if p == "" || len(p) > MaxForwardPath || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsRune(p, '\\') {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] <= 0x20 || p[i] >= 0x7f {
			return false
		}
	}
	return true
}

// ValidProxyHost accepts an exact lowercase DNS name with at least two labels.
func ValidProxyHost(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidLoginHeader refuses names nginx or the app treat as transport or routing headers,
// and the other Ky headers.
func ValidLoginHeader(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	n := strings.ToLower(name)
	if n == "x-ky-user" {
		return true
	}
	for _, p := range []string{"x-ky-", "x-forwarded-", "content-", "proxy-", "sec-"} {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	switch n {
	case "host", "cookie", "set-cookie", "authorization", "connection", "keep-alive", "te", "trailer", "transfer-encoding",
		"upgrade", "x-real-ip", "forwarded", "x-original-uri", "origin", "referer", "user-agent", "accept", "range", "expect":
		return false
	}
	return true
}

// ValidBypassPrefix accepts a bypass prefix: an absolute path, not /, with no trailing /.
func ValidBypassPrefix(p string) bool {
	return len(p) > 1 && len(p) <= 128 && ForwardPath(p) && !strings.ContainsAny(p, "%?#;") && !strings.Contains(p, "..") && !strings.HasSuffix(p, "/")
}
