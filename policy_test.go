package csp

import (
	"testing"
)

const (
	samplePolicy = `default-src https://cdn.example.net; frame-src 'none'; object-src 'none'`
)

func TestParse(t *testing.T) {
	p, err := Parse(samplePolicy)
	if err != nil {
		t.Fatal("Parse:", err)
	}
	if p.v[DirDefault][0] != `https://cdn.example.net` {
		t.Fatalf("SRC %s missmatch: %s", DirDefault, `https://cdn.example.net`)
	}
}
