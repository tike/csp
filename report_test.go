package csp

import (
	"encoding/json"
	"testing"
)

const (
	sampleReport = `
	{
	  "csp-report": {
	    "document-uri": "http://example.org/page.html",
	    "referrer": "http://evil.example.com/haxor.html",
	    "blocked-uri": "http://evil.example.com/image.png",
	    "violated-directive": "default-src 'self'",
	    "original-policy": "default-src 'self'; report-uri http://example.org/csp-report.cgi"
	  }
	}`
)

func TestReportDecode(t *testing.T) {
	var r ReportObj

	err := json.Unmarshal([]byte(sampleReport), &r)
	if err != nil {
		t.Fatal("unmarshal csp report:", err)
	}
}
