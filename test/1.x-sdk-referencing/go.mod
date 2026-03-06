module phase-ref-test-v1

go 1.20

require github.com/phasehq/golang-sdk v0.0.0

replace github.com/phasehq/golang-sdk => /tmp/phase-1.x-sdk

require github.com/jamesruan/sodium v1.0.14 // indirect
