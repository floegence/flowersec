package sessionv3

import "testing"

func TestPreviousVersionUnreliableDatagramsAreRecognized(t *testing.T) {
	previousMagic := []byte{'F', 'S', 'D', '2', 3}
	previousVersion := []byte{'F', 'S', 'D', '3', 2}
	current := []byte{'F', 'S', 'D', '3', 3}
	ordinaryInvalid := []byte{'n', 'o', 'i', 's', 'e'}

	for name, wire := range map[string][]byte{
		"previous magic":   previousMagic,
		"previous version": previousVersion,
	} {
		if !isPreviousVersionUnreliableDatagram(wire) {
			t.Fatalf("%s was not recognized", name)
		}
	}
	for name, wire := range map[string][]byte{
		"current": current,
		"noise":   ordinaryInvalid,
	} {
		if isPreviousVersionUnreliableDatagram(wire) {
			t.Fatalf("%s was incorrectly recognized", name)
		}
	}
}
