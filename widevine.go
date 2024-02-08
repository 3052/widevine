package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/hex"
   "errors"
   "github.com/chmike/cmac-go"
   "io"
   "net/http"
)

func (c Cdm) Keys(p Poster) (License, error) {
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
   if head, ok := p.RequestHeader(); ok {
      req.Header = head
   }
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   if res.StatusCode != http.StatusOK {
      return nil, errors.New(res.Status)
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
   return c.response(signed)
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

type SystemId [16]uint8

func (s SystemId) String() string {
   return hex.EncodeToString(s[:])
}

type Type [4]byte

func (t Type) String() string {
   return string(t[:])
}

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, bool)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

func (c Cdm) request_signed() ([]byte, error) {
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

// wikipedia.org/wiki/Encrypted_Media_Extensions#Content_Decryption_Modules
type Cdm struct {
   block cipher.Block
   license_request []byte
   private_key     *rsa.PrivateKey
}

func (c *Cdm) response(signed []byte) (License, error) {
   var message protobuf.Message // SignedMessage
   err := message.Consume(signed)
   if err != nil {
      return nil, err
   }
   session_key, err := func() ([]byte, error) {
      v, ok := message.GetBytes(4) // bytes session_key
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
   license, ok := message.Get(2) // License
   if !ok {
      return nil, errors.New("License")
   }
   return License(license), nil
}

type License protobuf.Message

type KeyContainer struct {
   m protobuf.Message
}

func (p Pssh) Key(l License) (*KeyContainer, bool) {
   for _, field := range l {
      if key, ok := field.Get(3); ok { // KeyContainer key
         // this field is optional:
         // optional bytes id = 1;
         // but CONTENT keys should always have it
         if id, ok := key.GetBytes(1); ok {
            if bytes.Equal(id, p.Key_id) {
               return &KeyContainer{key}, true
            }
         }
      }
   }
   return nil, false
}

func (c Cdm) Decrypt(k KeyContainer) ([]byte, bool) {
   if iv, ok := k.m.GetBytes(2); ok { // bytes iv
      if key, ok := k.m.GetBytes(3); ok { // bytes key
         cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(key, key)
         return unpad(key), true
      }
   }
   return nil, false
}
