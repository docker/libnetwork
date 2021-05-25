package dns

import (
	"strconv"
	"testing"
)

func TestIsIPv4Localhost(t *testing.T) {
	ips := []struct {
		ip     string
		expect bool
	}{
		{
			ip:     "127.0.0.1",
			expect: true,
		},
		{
			ip: "192.168.0.1",
		},
		{
			ip: "localhost",
		},
		{
			ip: "::1",
		},
		{
			ip:     "127.0.0.3",
			expect: true,
		},
	}

	for _, v := range ips {
		result := IsIPv4Localhost(v.ip)
		if result != v.expect {
			t.Fatalf("Expected return %s,but got %s", strconv.FormatBool(v.expect), strconv.FormatBool(result))
		}

	}
}
