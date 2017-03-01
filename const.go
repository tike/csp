package csp

// Header fields used to communicate CSP
const (
	Header   = "Content-Security-Policy"
	HeaderRO = "Content-Security-Policy-Report-Only"
)

// Directive names
const (
	DirDefault = "default-src"
	DirScript  = "script-src"
	DirObject  = "object-src"
	DirStyle   = "style-src"
	DirImage   = "img-src"
	DirMedia   = "media-src"
	DirFrame   = "frame-src"
	DirFont    = "font-src"
	DirConnect = "connect-src"
	DirSandbox = "sandbox"
	DirReport  = "report-uri"
)

// Directive keyword values
const (
	ValNone         = "'none'"
	ValAny          = "*"
	ValSelf         = "'self'"
	ValUnsafeInline = "'unsafe-inline'"
	ValUnsafeEval   = "'unsafe-eval'"
)

// Nonce and hash values
const (
	ValNoncePrfx  = "nonce"
	ValHashSHA256 = "sha256"
	ValHashSHA384 = "sha384"
	ValHashSHA512 = "sha512"
)

const (
	ReportKey = "csp-report"
)
