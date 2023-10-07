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

func (m Module) signed_response(response []byte) ([]byte, error) {
   mes, err := protobuf.Consume(response) // message SignedMessage
   if err != nil {
      return nil, err
   }
   session_key, err := func() ([]byte, error) {
      v, ok := mes.Bytes(4) // bytes session_key
      if !ok {
         return nil, errors.New("session_key")
      }
      return rsa.DecryptOAEP(sha1.New(), nil, m.private_key, v, nil)
   }()
   if err != nil {
      return nil, err
   }
   block, err := func() (cipher.Block, error) {
      var b []byte
      b = append(b, 1)
      b = append(b, "ENCRYPTION"...)
      b = append(b, 0)
      b = append(b, m.license_request...)
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
   if !mes.Message(2) { // License
      return nil, errors.New("License")
   }
   for _, f := range mes {
      if f.Number == 3 { // KeyContainer key
         if key, ok := f.Message(); ok {
            id, _ := key.Bytes(1) // optional bytes id
            iv, ok := key.Bytes(2) // bytes iv
            if !ok {
               return nil, errors.New("IV")
            }
            key, ok := key.Bytes(3) // bytes key
            if !ok {
               return nil, errors.New("key")
            }
            cipher.NewCBCDecrypter(block, iv).CryptBlocks(key, key)
            if bytes.Equal(id, m.key_ID) {
               // return session_key, IV, key
               return unpad(key), nil
            }
         }
      }
   }
   return nil, errors.New("key ID not found")
}
