package csp

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type Policy struct {
	m sync.Mutex
	v map[string][]string
}

func NewPolicy() *Policy {
	return &Policy{
		v: make(map[string][]string),
	}
}

func (p *Policy) Set(dir string, sources ...string) *Policy {
	p.m.Lock()
	defer p.m.Unlock()

	if legalKey(dir) {
		p.v[dir] = sources
	}

	return p
}

func (p *Policy) Add(dir string, sources ...string) *Policy {
	p.m.Lock()
	defer p.m.Unlock()

	if legalKey(dir) {
		p.v[dir] = append(p.v[dir], sources...)
	}
	return p
}

func (p Policy) String() string {
	p.m.Lock()
	defer p.m.Unlock()

	polTokens := make([]string, 0, len(p.v)+1)

	for directive, sourceList := range p.v {
		polTokens = append(polTokens, directive+" "+strings.Join(sourceList, " "))
	}

	return strings.Join(polTokens, "; ")
}

func Parse(encPolicy string) (*Policy, error) {
	rawDirectives := strings.Split(encPolicy, ";")

	p := NewPolicy()
	for _, rawDirective := range rawDirectives {
		parts := strings.Split(strings.TrimSpace(rawDirective), " ")

		name, err := parseName(parts[0])
		if err != nil {
			return nil, err
		}

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
	if len(sl) == 0 {
		return []string{}, nil
	}

	sources := make([]string, 0, len(sl))
	for _, sle := range sl {
		val := strings.ToLower(strings.TrimSpace(sle))
		switch {
		case strings.HasPrefix(val, ValNoncePrfx):
			fallthrough
		case strings.HasPrefix(val, ValHashSHA256):
			fallthrough
		case strings.HasPrefix(val, ValHashSHA384):
			fallthrough
		case strings.HasPrefix(val, ValHashSHA512):
			fallthrough
		case ValNone == val:
			fallthrough
		case ValAny == val:
			fallthrough
		case ValSelf == val:
			fallthrough
		case ValUnsafeEval == val:
			fallthrough
		case ValUnsafeInline == val:
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

func legalKey(key string) bool {
	switch key {
	case DirConnect, DirDefault, DirFont, DirFrame, DirImage, DirMedia,
		DirObject, DirSandbox, DirScript, DirReport:
		return true
	}
	return false
}
