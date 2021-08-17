# go-update: Build self-updating Go programs [![godoc reference](https://godoc.org/github.com/Press-One/go-update?status.png)](https://godoc.org/github.com/Press-One/go-update)

> NOTE: Original work at github.com/inconshreveable/go-update, modified for the needs within Quorum project

Package update provides functionality to implement secure, self-updating Go programs (or other single-file targets)
A program can update itself by replacing its executable file with a new version.

It provides the flexibility to implement different updating user experiences
like auto-updating, or manual user-initiated updates. It also boasts
advanced features like binary patching and code signing verification.

Example of updating from a URL:

```go
import (
    "fmt"
    "net/http"

    "github.com/Press-One/go-update"
)

func doUpdate(url string) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    err := update.Apply(resp.Body, update.Options{})
    if err != nil {
        // error handling
    }
    return err
}
```

## Features

- Cross platform support (Windows too!)
- Binary patch application
- Checksum verification
- Code signing verification
- Support for updating arbitrary files

