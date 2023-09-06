package widevine

import (
   "154.pages.dev/encoding/protobuf"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "github.com/chmike/cmac-go"
)

type Container struct {
   // bytes Iv = 2;
   IV []byte
   // bytes Key = 3;
   Key []byte
   // KeyType Type = 4;
   Type uint64
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

func (m Module) signed_response(response []byte) (Containers, error) {
   // key
   signed_response, err := protobuf.Consume(response)
   if err != nil {
      return nil, err
   }
   raw_key, err := signed_response.Bytes(4)
   if err != nil {
      return nil, err
   }
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, m.private_key, raw_key, nil,
   )
   if err != nil {
      return nil, err
   }
   // message
   var enc_key []byte
   enc_key = append(enc_key, 1)
   enc_key = append(enc_key, "ENCRYPTION"...)
   enc_key = append(enc_key, 0)
   enc_key = append(enc_key, m.license_request...)
   enc_key = append(enc_key, 0, 0, 0, 0x80)
   // CMAC
   key_CMAC, err := cmac.New(aes.NewCipher, session_key)
   if err != nil {
      return nil, err
   }
   key_CMAC.Write(enc_key)
   key_cipher, err := aes.NewCipher(key_CMAC.Sum(nil))
   if err != nil {
      return nil, err
   }
   msg, err := signed_response.Message(2)
   if err != nil {
      return nil, err
   }
   var cons Containers
   msg.Messages(3, func(key protobuf.Message) {
      var c Container
      c.IV, err = key.Bytes(2)
      if err != nil {
         return
      }
      c.Key, err = key.Bytes(3)
      if err != nil {
         return
      }
      c.Type, err = key.Varint(4)
      if err != nil {
         return
      }
      cipher.NewCBCDecrypter(key_cipher, c.IV).CryptBlocks(c.Key, c.Key)
      c.Key = unpad(c.Key)
      cons = append(cons, c)
   })
   if err != nil {
      return nil, err
   }
   return cons, nil
}
