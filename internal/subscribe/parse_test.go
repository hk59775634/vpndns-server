package subscribe

import "testing"

func TestParseSubscribeLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"||*. myid.gov.au^", "*.myid.gov.au", true},
		{"||*.*google.com^", "*.google.com", true},
		{"||*.0086visa.com^", "*.0086visa.com", true},
		{"||example.com^", "example.com", true},
		{"  ||foo.bar^  ", "foo.bar", true},
		{"# comment", "", false},
		{"! exception", "", false},
		{"", "", false},
		{"example.org plain", "example.org", true},
		{"cosmetic##selector", "", false},
	}
	for _, tc := range tests {
		got, ok := parseSubscribeLine(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseSubscribeLine(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
