package csp

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type Policy struct {
	m      sync.Mutex
	v      map[string][]string
	Report []*url.URL
}

func (p Policy) String() string {
	polTokens := make([]string, 0, len(p.v)+1)

	for directive, sourceList := range p.v {
		polTokens = append(polTokens, directive+" "+strings.Join(sourceList, " "))
	}

	if p.Report != nil {
		uris := []string{DirReport}
		for _, uri := range p.Report {
			uris = append(uris, uri.String())
		}
		polTokens = append(polTokens, strings.Join(uris, " "))
	}

	return strings.Join(polTokens, ";")
}

func (p *Policy) Set(dir string, sources ...string) {
	p.m.Lock()
	defer p.m.Unlock()

	p.v[dir] = sources
}

func (p *Policy) Add(dir string, sources ...string) {
	p.m.Lock()
	defer p.m.Unlock()

	p.v[dir] = append(p.v[dir], sources...)
}

func NewPolicy() *Policy {
	return &Policy{
		v: make(map[string][]string),
	}
}

func Parse(encPolicy string) (*Policy, error) {
	rawDirectives := strings.Split(encPolicy, ";")

	p := NewPolicy()
	for _, rawDirective := range rawDirectives {

		parts := strings.SplitN(strings.TrimSpace(rawDirective), " ", 2)

		name, err := parseName(parts[0])
		if err != nil {
			return nil, err
		}

		switch name {
		case DirReport:
			if len(parts) == 1 {
				p.Report = []*url.URL{}
				break
			}
			repList, err := parseReportList(parts[1])
			if err != nil {
				return nil, err
			}
			p.Report = repList

		case DirConnect, DirDefault, DirFont, DirFrame, DirImage, DirMedia,
			DirObject, DirSandbox, DirScript:
			if _, there := p.v[name]; there {
				break
			}
			if len(parts) == 1 {
				p.v[name] = []string{}
				break
			}
			sourceList, err := parseSourceList(parts[1])
			if err != nil {
				return nil, err
			}
			p.v[name] = sourceList
		}

	}
	return p, nil
}

func parseName(dir string) (string, error) {
	dir = strings.ToLower(dir)
	switch dir {
	case DirConnect, DirDefault, DirFont, DirFrame, DirImage, DirMedia,
		DirObject, DirReport, DirSandbox, DirScript, DirStyle:
		return dir, nil

	}
	return "", fmt.Errorf("csp: invalid directive name %s", dir)
}

func parseSourceList(val string) ([]string, error) {
	sl := strings.Split(strings.TrimSpace(val), " ")
	sources := make([]string, 0, len(sl))

	for _, sle := range sl {
		switch val := strings.ToLower(sle); val {
		case ValNone:
			return []string{}, nil
		case ValAny, ValSelf, ValUnsafeEval, ValUnsafeInline:
			sources = append(sources, val)
		default:
			u, err := url.Parse(val)
			if err != nil {
				return nil, err
			}
			sources = append(sources, u.String())
		}
	}
	return sources, nil
}

func parseReportList(list string) ([]*url.URL, error) {
	list = strings.ToLower(list)
	vals := make([]*url.URL, 0, 3)

	for _, val := range strings.Split(list, " ") {
		uri, err := url.Parse(val)
		if err != nil {
			return nil, err
		}
		vals = append(vals, uri)
	}
	return vals, nil
}
