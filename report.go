package csp

import (
	"net/url"
)

type Report struct {
	Document *url.URL `json:"document-uri"`
	Referrer *url.URL `json:"referrer"`

	Blocked *url.URL `json:"blocked-uri"`
	Status  int      `json:"status-code"`

	Effective string `json:"effective-directive"`
	Violated  string `json:"violated-directive"`

	Policy *Policy `json:"original-policy"`

	Source
}

type Source struct {
	File   string `json:"source-file"`
	Line   int    `json:"line-number"`
	Column int    `json:"column-number"`
}

type ReportObj struct {
	Report Report `json:"csp-report"`
}
