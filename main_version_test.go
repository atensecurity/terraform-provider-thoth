package main

import (
	"os"
	"strings"
	"testing"
)

func TestVersionNotDevInStrictReleaseMode(t *testing.T) {
	if os.Getenv("THOTH_RELEASE_STRICT_VERSION") != "1" {
		t.Skip("set THOTH_RELEASE_STRICT_VERSION=1 to enforce non-dev release version")
	}

	v := strings.TrimSpace(version)
	if v == "" || v == "dev" {
		t.Fatalf("invalid release version %q: expected non-dev version injected via -ldflags", v)
	}
}
