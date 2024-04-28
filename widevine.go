package widevine

import (
   "154.pages.dev/protobuf"
   "crypto/x509"
   "encoding/pem"
   "net/http"
)

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

func new_cdm(d data, client_id, private_key []byte) (*CDM, error) {
   module := CDM{data: d}
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   module.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   // license_request
   var request protobuf.Message               // LicenseRequest
   request.AddBytes(1, client_id)             // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddBytes(1, d.pssh())
      })
   })
   module.license_request = request.Encode()
   return &module, nil
}

type KeyId []byte

func (k KeyId) CDM(client_id, private_key []byte) (*CDM, error) {
   return new_cdm(k, client_id, private_key)
}

func (k KeyId) key_id() ([]byte, error) {
   return k, nil
}

func (k KeyId) pssh() []byte {
   var m protobuf.Message
   m.AddBytes(2, []byte(k))
   return m.Encode()
}

type LicenseMessage struct {
   m protobuf.Message
}

type PSSH []byte

func (p PSSH) CDM(client_id, private_key []byte) (*CDM, error) {
   return new_cdm(p, client_id, private_key)
}

func (p PSSH) key_id() ([]byte, error) {
   var m protobuf.Message
   err := m.Consume(p)
   if err != nil {
      return nil, err
   }
   return <-m.GetBytes(2), nil
}

func (p PSSH) pssh() []byte {
   return p
}

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

type data interface {
   key_id() ([]byte, error)
   pssh() []byte
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}
