package widevine

import (
   "154.pages.dev/protobuf"
   "crypto/x509"
   "encoding/pem"
   "net/http"
)

// 2024-3-31: content ID is optional with all servers except Roku. with Roku,
// you can omit the PSSH completely, since its already embedded in the request
// URL. however if you do provide a key ID, you also have to provide a one byte
// content ID. any byte should work, but they use `*` so lets go with that
func (c *CDM) New(private_key, client_id, key_id []byte) error {
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   // key_id
   c.key_id = key_id
   // license_request
   var request protobuf.Message               // LicenseRequest
   request.AddBytes(1, client_id)             // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.Add(1, func(m *protobuf.Message) { // pssh_data
            m.AddBytes(2, key_id)
            m.AddBytes(4, []byte{'*'}) // content_id
         })
      })
   })
   c.license_request = request.Encode()
   return nil
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

type LicenseMessage struct {
   m protobuf.Message
}

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
