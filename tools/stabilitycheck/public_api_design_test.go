package main

import "testing"

func TestPortablePublicAPIDesignContract(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPublicAPIDesign(repoRoot); err != nil {
		t.Fatal(err)
	}
}
