package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
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
            if bytes.Equal(id, m.key_ID) {
               iv, ok := key.Bytes(2) // bytes iv
               if !ok {
                  return nil, errors.New("IV")
               }
               key, ok := key.Bytes(3) // bytes key
               if !ok {
                  return nil, errors.New("key")
               }
               cipher.NewCBCDecrypter(block, iv).CryptBlocks(key, key)
               return unpad(key), nil
            }
         }
      }
   }
   return nil, errors.New("key ID not found")
}

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
