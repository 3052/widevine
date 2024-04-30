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

type KeyId []byte

type LicenseMessage struct {
   m protobuf.Message
}

type PSSH []byte

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

func (c *CDM) New(d Data, client_id, private_key []byte) error {
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   // data
   c.data = d
   // license_request
   var request protobuf.Message               // LicenseRequest
   request.AddBytes(1, client_id)             // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddBytes(1, d.PSSH())
      })
   })
   c.license_request = request.Encode()
   return nil
}

type Data interface {
   KeyId() ([]byte, error)
   PSSH() []byte
}

func (k KeyId) KeyId() ([]byte, error) {
   return k, nil
}

func (k KeyId) PSSH() []byte {
   var m protobuf.Message
   m.AddBytes(2, []byte(k))
   return m.Encode()
}

func (p PSSH) KeyId() ([]byte, error) {
   var m protobuf.Message
   err := m.Consume(p)
   if err != nil {
      return nil, err
   }
   return <-m.GetBytes(2), nil
}

func (p PSSH) PSSH() []byte {
   return p
}
