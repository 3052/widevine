package widevine

import (
   "154.pages.dev/encoding/protobuf"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "errors"
   "github.com/chmike/cmac-go"
)

func (m Module) signed_response(response []byte) (Containers, error) {
   signed_message, err := protobuf.Consume(response) // message SignedMessage
   if err != nil {
      return nil, err
   }
   session_key, err := func() ([]byte, error) {
      v, ok := signed_message.Bytes(4) // bytes session_key
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
   license, ok := signed_message.Message(2) // License
   if !ok {
      return nil, errors.New("license")
   }
   var cons Containers
   for _, f := range license {
      if f.Number == 3 { // KeyContainer key
         if key, ok := f.Message(); ok {
            var c Container
            c.ID, _ = key.Bytes(1) // bytes id
            c.IV, _ = key.Bytes(2) // bytes iv
            c.Key, _ = key.Bytes(3) // bytes key
            c.Type, _ = key.Varint(4) // KeyType type
            c.Label, _ = key.String(12) // string track_label
            cipher.NewCBCDecrypter(block, c.IV).CryptBlocks(c.Key, c.Key)
            c.Key = unpad(c.Key)
            cons = append(cons, c)
         }
      }
   }
   return cons, nil
}
