package godnsbl

import (
	"testing"
)

// func TestSetResolver(t *testing.T) {
// 	err := SetResolver("ns1.swerve.co.nz", 53)

// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

func TestLookup(t *testing.T) {
	// good
	r := Lookup("shield1.mi2.co.nz", "8.8.8.8", 53)

	//bad
	//r := Lookup("203.118.158.158", "8.8.8.8", 53)

	t.Logf("Lookup: %v", r)
}
