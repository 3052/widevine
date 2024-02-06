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

func (c CDM) Key(post Poster) ([]byte, error) {
   address, ok := post.Request_URL()
   if !ok {
      return nil, errors.New("Poster.Request_URL")
   }
   signed, err := func() ([]byte, error) {
      b, err := c.request_signed()
      if err != nil {
         return nil, err
      }
      return post.Request_Body(b)
   }()
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", address, bytes.NewReader(signed))
   if err != nil {
      return nil, err
   }
   if head, ok := post.Request_Header(); ok {
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
   signed, err = func() ([]byte, error) {
      b, err := io.ReadAll(res.Body)
      if err != nil {
         return nil, err
      }
      return post.Response_Body(b)
   }()
   if err != nil {
      return nil, err
   }
   return c.response(signed)
}

type Poster interface {
   Request_URL() (string, bool)
   Request_Header() (http.Header, bool)
   Request_Body([]byte) ([]byte, error)
   Response_Body([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

func (c *CDM) New(private_key []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   return nil
}

func (c *CDM) Key_ID(client_id, key_id []byte) {
   // key_id
   c.key_id = key_id
   // license_request
   var request protobuf.Message // LicenseRequest
   request.AddBytes(1, client_id) // client_id
   request.AddFunc(2, func(m *protobuf.Message) { // content_id
      m.AddFunc(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddFunc(1, func(m *protobuf.Message) { // pssh_data
            m.AddBytes(2, key_id)
         })
      })
   })
   c.license_request = request.Encode()
}

// some sites use content_id, in which case you need PSSH
func (c *CDM) PSSH(client_id, pssh []byte) error {
   if len(pssh) <= 31 {
      return errors.New("CDM.PSSH")
   }
   pssh = pssh[32:]
   // key_id
   var pssh_data protobuf.Message // WidevinePsshData
   err := pssh_data.Consume(pssh)
   if err != nil {
      return err
   }
   var ok bool
   c.key_id, ok = pssh_data.GetBytes(2)
   if !ok {
      return errors.New("key_ids")
   }
   // license_request 
   var request protobuf.Message // LicenseRequest
   request.AddBytes(1, client_id) // client_id
   request.AddFunc(2, func(m *protobuf.Message) { // content_id
      m.AddFunc(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddBytes(1, pssh) // pssh_data
      })
   })
   c.license_request = request.Encode()
   return nil
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

// wikipedia.org/wiki/Encrypted_Media_Extensions#Content_Decryption_Modules
type CDM struct {
   key_id          []byte
   license_request []byte
   private_key     *rsa.PrivateKey
}

func (c CDM) request_signed() ([]byte, error) {
   hash := sha1.Sum(c.license_request)
   signature, err := rsa.SignPSS(
      no_operation{},
      c.private_key,
      crypto.SHA1,
      hash[:],
      &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
   )
   if err != nil {
      return nil, err
   }
   var signed protobuf.Message // SignedMessage
   signed.AddBytes(2, c.license_request)
   signed.AddBytes(3, signature)
   return signed.Encode(), nil
}

