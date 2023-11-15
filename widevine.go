package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "errors"
   "io"
   "net/http"
)

type Module struct {
   key_ID          []byte
   license_request []byte
   private_key     *rsa.PrivateKey
}

// some sites use content_id, in which case you can provide PSSH instead of
// key_ID
func New_Module(private_key, client_ID, key_ID, pssh []byte) (*Module, error) {
   var mod Module
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   mod.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   // license_request
   var req protobuf.Message // LicenseRequest
   req.Add_Bytes(1, client_ID) // client_id
   if len(pssh) >= 32 {
      pssh = pssh[32:]
      req.Add(2, func(m *protobuf.Message) { // content_id
         m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
            m.Add_Bytes(1, pssh) // pssh_data
         })
      })
      mod.key_ID, err = func() ([]byte, error) {
         m, err := protobuf.Consume(pssh) // WidevinePsshData
         if err != nil {
            return nil, err
         }
         v, ok := m.Bytes(2)
         if !ok {
            return nil, errors.New("key_ids")
         }
         return v, nil
      }()
      if err != nil {
         return nil, err
      }
   } else {
      req.Add(2, func(m *protobuf.Message) { // content_id
         m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
            m.Add(1, func(m *protobuf.Message) { // pssh_data
               m.Add_Bytes(2, key_ID)
            })
         })
      })
      mod.key_ID = key_ID
   }
   mod.license_request = req.Append(nil)
   return &mod, nil
}

func (m Module) Key(post Poster) ([]byte, error) {
   body, err := func() ([]byte, error) {
      b, err := m.signed_request()
      if err != nil {
         return nil, err
      }
      return post.Request_Body(b)
   }()
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", post.Request_URL(), bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   if head := post.Request_Header(); head != nil {
      req.Header = head
   }
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   if res.StatusCode != http.StatusOK {
      var b bytes.Buffer
      res.Write(&b)
      return nil, errors.New(b.String())
   }
   body, err = func() ([]byte, error) {
      b, err := io.ReadAll(res.Body)
      if err != nil {
         return nil, err
      }
      return post.Response_Body(b)
   }()
   if err != nil {
      return nil, err
   }
   return m.signed_response(body)
}

func (m Module) signed_request() ([]byte, error) {
   hash := sha1.Sum(m.license_request)
   signature, err := rsa.SignPSS(
      no_operation{},
      m.private_key,
      crypto.SHA1,
      hash[:],
      &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
   )
   if err != nil {
      return nil, err
   }
   var signed_request protobuf.Message
   signed_request.Add_Bytes(2, m.license_request)
   signed_request.Add_Bytes(3, signature)
   return signed_request.Append(nil), nil
}

type Poster interface {
   Request_URL() string
   Request_Header() http.Header
   Request_Body([]byte) ([]byte, error)
   Response_Body([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}
func unpad(buf []byte) []byte {
   if len(buf) >= 1 {
      pad := buf[len(buf)-1]
      if len(buf) >= int(pad) {
         buf = buf[:len(buf)-int(pad)]
      }
   }
   return buf
}
