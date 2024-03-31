package widevine

import (
   "154.pages.dev/protobuf"
   "crypto/x509"
   "encoding/pem"
   "net/http"
)

func (p PSSH) CDM(private_key, client_id []byte) (*CDM, error) {
   var module CDM
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   module.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   // key_id
   module.key_id = p.key_id()
   // license_request
   var request protobuf.Message               // LicenseRequest
   request.AddBytes(1, client_id)             // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddBytes(1, p.Data) // pssh_data
      })
   })
   module.license_request = request.Encode()
   return &module, nil
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

type LicenseMessage struct {
   m protobuf.Message
}

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

// some sites use content_id, in which case you need PSSH
type PSSH struct {
   Data []byte
   m protobuf.Message
}

func (p *PSSH) Consume() error {
   return p.m.Consume(p.Data)
}

// Cannot be used in conjunction with content_id. all of the Widevine PSSH I
// have seen so far are single `key_id`, so we are going to implement that for
// now, because its not clear what the logic would be with multiple key_ids
func (p PSSH) key_id() []byte {
   return <-p.m.GetBytes(2)
}
