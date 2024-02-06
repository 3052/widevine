package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "errors"
   "github.com/chmike/cmac-go"
)

func (c CDM) response(signed []byte) ([]byte, error) {
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
   block, err := func() (cipher.Block, error) {
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
   for _, field := range license {
      if key, ok := field.Get(3); ok { // KeyContainer key
         id := func() bool {
            if v, ok := key.GetBytes(1); ok { // optional bytes id
               return bytes.Equal(v, c.key_id)
            }
            return true
         }
         if id() {
            iv, ok := key.GetBytes(2) // bytes iv
            if !ok {
               return nil, errors.New("IV")
            }
            key, ok := key.GetBytes(3) // bytes key
            if !ok {
               return nil, errors.New("key")
            }
            cipher.NewCBCDecrypter(block, iv).CryptBlocks(key, key)
            return unpad(key), nil
         }
      }
   }
   return nil, errors.New("KeyContainer")
}
