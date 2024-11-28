# Overview

package `widevine`

## Index

- [Types](#types)
  - [type Cdm](#type-cdm)
    - [func (c \*Cdm) Key(post Poster, key_id []byte) ([]byte, error)](#func-cdm-key)
    - [func (c \*Cdm) New(private_key, client_id, pssh []byte) error](#func-cdm-new)
  - [type Poster](#type-poster)
  - [type Pssh](#type-pssh)
    - [func (p Pssh) Marshal() []byte](#func-pssh-marshal)
- [Source files](#source-files)

## Types

### type [Cdm](./widevine.go#L169)

```go
type Cdm struct {
  // contains filtered or unexported fields
}
```

### func (\*Cdm) [Key](./widevine.go#L19)

```go
func (c *Cdm) Key(post Poster, key_id []byte) ([]byte, error)
```

### func (\*Cdm) [New](./widevine.go#L83)

```go
func (c *Cdm) New(private_key, client_id, pssh []byte) error
```

### type [Poster](./widevine.go#L184)

```go
type Poster interface {
  RequestUrl() (string, bool)
  RequestHeader() (http.Header, error)
  WrapRequest([]byte) ([]byte, error)
  UnwrapResponse([]byte) ([]byte, error)
}
```

### type [Pssh](./pssh.go#L5)

```go
type Pssh struct {
  ContentId []byte
  KeyId     []byte
}
```

### func (Pssh) [Marshal](./pssh.go#L10)

```go
func (p Pssh) Marshal() []byte
```

## Source files

[pssh.go](./pssh.go)
[widevine.go](./widevine.go)
