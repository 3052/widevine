package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/base64"
   "errors"
   "github.com/chmike/cmac-go"
   "io"
   "log/slog"
   "net/http"
)

func (c CDM) Key(m *LicenseMessage) ([]byte, bool) {
   for container := range m.m.Get(3) { // KeyContainer key
      // this field is: optional bytes id = 1;
      // but CONTENT keys should always have it
      id, ok := <-container.GetBytes(1)
      if !ok {
         continue
      }
      if !bytes.Equal(id, c.key_id) {
         continue
      }
      iv, ok := <-container.GetBytes(2)
      if !ok {
         continue
      }
      key, ok := <-container.GetBytes(3)
      if !ok {
         continue
      }
      cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(key, key)
      return unpad(key), true
   }
   return nil, false
}

// wikipedia.org/wiki/Encrypted_Media_Extensions#Content_Decryption_Modules
type CDM struct {
   block           cipher.Block
   key_id          []byte
   license_request []byte
   private_key     *rsa.PrivateKey
}

func (c *CDM) License(p Poster) (*LicenseMessage, error) {
   address, ok := p.RequestUrl()
   if !ok {
      return nil, errors.New("Poster.RequestUrl")
   }
   signed, err := func() ([]byte, error) {
      b, err := c.request_signed()
      if err != nil {
         return nil, err
      }
      return p.RequestBody(b)
   }()
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", address, bytes.NewReader(signed))
   if err != nil {
      return nil, err
   }
   req.Header, err = p.RequestHeader()
   if err != nil {
      return nil, err
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
      return p.ResponseBody(b)
   }()
   if err != nil {
      return nil, err
   }
   slog.Debug("license", "response", base64.StdEncoding.EncodeToString(signed))
   return c.response(signed)
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

func (c *CDM) response(signed []byte) (*LicenseMessage, error) {
   var message protobuf.Message // SignedMessage
   err := message.Consume(signed)
   if err != nil {
      return nil, err
   }
   session_key, err := func() ([]byte, error) {
      v, ok := <-message.GetBytes(4)
      if !ok {
         return nil, errors.New("session_key")
      }
      return rsa.DecryptOAEP(sha1.New(), nil, c.private_key, v, nil)
   }()
   if err != nil {
      return nil, err
   }
   c.block, err = func() (cipher.Block, error) {
      var b []byte
      b = append(b, 1)
      b = append(b, "ENCRYPTION"...)
      b = append(b, 0)
      b = append(b, c.license_request...)
      b = append(b, 0, 0, 0, 0x80)
      h, err := cmac.New(aes.NewCipher, session_key)
      if err != nil {
         return nil, err
      }
      h.Write(b)
      return aes.NewCipher(h.Sum(nil))
   }()
   if err != nil {
      return nil, err
   }
   // this is listed as: optional bytes msg = 2;
   // but assuming the type is: LICENSE = 2;
   // the result is actually: optional License msg = 2;
   license, ok := <-message.Get(2)
   if !ok {
      return nil, errors.New("License")
   }
   return &LicenseMessage{license}, nil
}
