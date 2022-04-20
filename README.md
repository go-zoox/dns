# Retry - Catch Panic In Retries

[![PkgGoDev](https://pkg.go.dev/badge/github.com/go-zoox/retry)](https://pkg.go.dev/github.com/go-zoox/retry)
[![Build Status](https://github.com/go-zoox/retry/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/go-zoox/retry/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-zoox/retry)](https://goreportcard.com/report/github.com/go-zoox/retry)
[![Coverage Status](https://coveralls.io/repos/github/go-zoox/retry/badge.svg?branch=master)](https://coveralls.io/github/go-zoox/retry?branch=master)
[![GitHub issues](https://img.shields.io/github/issues/go-zoox/retry.svg)](https://github.com/go-zoox/retry/issues)
[![Release](https://img.shields.io/github/tag/go-zoox/retry.svg?label=Release)](https://github.com/go-zoox/retry/tags)

## Installation
To install the package, run:
```bash
go get github.com/go-zoox/retry
```

## Getting Started

```go
err := retry.Retry(
	func() {
		c++
		if c < 3 {
			panic("panic error")
		}
	},
	3,
	time.Millisecond,
)
```

## License
GoZoox is released under the [MIT License](./LICENSE).