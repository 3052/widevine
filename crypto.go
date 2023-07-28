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

func (m Module) signed_response(response []byte) (Containers, error) {
   // key
   signed_response, err := protobuf.Unmarshal(response)
   if err != nil {
      return nil, err
   }
   _, raw_key := signed_response.Bytes(4)
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
   var cons Containers
   _, msg := signed_response.Message(2)
   for {
      i, key := msg.Message(3)
      if i == -1 {
         return cons, nil
      }
      var con Container
      _, iv := key.Bytes(2)
      _, con.Key = key.Bytes(3)
      _, con.Type = key.Uvarint(4)
      cipher.NewCBCDecrypter(key_cipher, iv).CryptBlocks(con.Key, con.Key)
      con.Key = unpad(con.Key)
      cons = append(cons, con)
      msg = msg[i+1:]
   }
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
   signed_request := protobuf.Message{
      protobuf.Number(2).Bytes(m.license_request),
      protobuf.Number(3).Bytes(signature),
   }
   return signed_request.Append(nil), nil
}

