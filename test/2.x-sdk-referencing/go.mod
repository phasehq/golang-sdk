module phase-ref-test-v2

go 1.22

toolchain go1.24.13

require github.com/phasehq/golang-sdk/v2 v2.0.0

replace github.com/phasehq/golang-sdk/v2 => ../..

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
