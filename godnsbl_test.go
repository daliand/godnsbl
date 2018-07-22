package godnsbl

import (
	"net"
	"testing"
)

// func TestSetResolver(t *testing.T) {
// 	err := SetResolver("ns1.swerve.co.nz", 53)

// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

func TestLookup(t *testing.T) {
	ip := net.ParseIP("203.118.158.158")
	r := Lookup(ip)
	t.Logf("Lookup: %v", r)
}
