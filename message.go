package widevine

import (
   "154.pages.dev/protobuf"
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
)

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

func (p PSSH) CDM(private_key, client_id []byte) (*CDM, error) {
   var module CDM
   // key_id
   module.key_id = p.Key_ID
   // license_request
   var request protobuf.Message // LicenseRequest
   request.AddBytes(1, client_id) // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.Add(1, func(m *protobuf.Message) { // pssh_data
            m.AddBytes(2, p.Key_ID)
            m.AddBytes(4, p.content_id)
         })
      })
   })
   module.license_request = request.Encode()
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   module.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   return &module, nil
}
