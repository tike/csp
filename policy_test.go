package csp

import (
	"testing"
)

const (
	samplePolicy = `default-src https://cdn.example.net; frame-src 'none'; object-src sha256-blaxyz`
)

func TestParse(t *testing.T) {
	p, err := Parse(samplePolicy)
	if err != nil {
		t.Fatal("Parse:", err)
	}
	if p.v[DirDefault][0] != `https://cdn.example.net` {
		t.Fatalf("SRC %s missmatch: %s", DirDefault, `https://cdn.example.net`)
	}
	if p.v[DirFrame][0] != `'none'` {
		t.Fatalf("SRC %s missmatch: %s", DirDefault, `'none'`)
	}
	if p.v[DirObject][0] != `sha256-blaxyz` {
		t.Fatalf("SRC %s missmatch: %s", DirDefault, `sha256-blaxyz`)
	}
}
