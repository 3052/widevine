package widevine

import (
   "41.neocities.org/protobuf"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "github.com/chmike/cmac-go"
   "iter"
)

type Pssh struct {
   ContentId []byte
   KeyIds    [][]byte
}

type Cdm struct {
   license_request []byte
   private_key     *rsa.PrivateKey
}

func (c *Cdm) New(private_key, client_id, pssh1 []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      // L1
      key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
      if err != nil {
         return err
      }
      c.private_key = key.(*rsa.PrivateKey)
   }
   c.license_request = protobuf.Message{ // LicenseRequest
      {1, protobuf.Bytes(client_id)}, // ClientIdentification client_id
      {2, protobuf.Message{ // ContentIdentification content_id
         {1, protobuf.Message{ // WidevinePsshData widevine_pssh_data
            {1, protobuf.Bytes(pssh1)},
         }},
      }},
   }.Marshal()
   return nil
}

func (c *Cdm) RequestBody() ([]byte, error) {
   hash := sha1.Sum(c.license_request)
   signature, err := rsa.SignPSS(
      rand{},
      c.private_key,
      crypto.SHA1,
      hash[:],
      &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
   )
   if err != nil {
      return nil, err
   }
   // SignedMessage
   var signed protobuf.Message
   // kktv.me
   // type: LICENSE_REQUEST
   signed.AddVarint(1, 1)
   // LicenseRequest msg
   signed.AddBytes(2, c.license_request)
   // bytes signature
   signed.AddBytes(3, signature)
   return signed.Marshal(), nil
}

func (c *Cdm) Block(body ResponseBody) (cipher.Block, error) {
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, c.private_key, body.session_key(), nil,
   )
   if err != nil {
      return nil, err
   }
   hash, err := cmac.New(aes.NewCipher, session_key)
   if err != nil {
      return nil, err
   }
   var data []byte
   data = append(data, 1)
   data = append(data, "ENCRYPTION"...)
   data = append(data, 0)
   data = append(data, c.license_request...)
   // hash.Size()
   data = append(data, 0, 0, 0, 128)
   // github.com/chmike/cmac-go/blob/v1.1.0/cmac.go#L114-L133
   hash.Write(data)
   return aes.NewCipher(hash.Sum(nil))
}

type KeyContainer [1]protobuf.Message

func (k KeyContainer) Key(block cipher.Block) []byte {
   for data := range k[0].GetBytes(3) {
      cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(data, data)
      return unpad(data)
   }
   return nil
}

func (p *Pssh) Marshal() []byte {
   var message protobuf.Message
   for _, key_id := range p.KeyIds {
      message.AddBytes(2, key_id)
   }
   if len(p.ContentId) >= 1 {
      message.AddBytes(4, p.ContentId)
   }
   return message.Marshal()
}

func (r *ResponseBody) Unmarshal(data []byte) error {
   return r[0].Unmarshal(data)
}

// SignedMessage
// LICENSE = 2;
type ResponseBody [1]protobuf.Message

func (rand) Read(data []byte) (int, error) {
   return len(data), nil
}

type rand struct{}

///

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

func (k KeyContainer) Id() []byte {
   for data := range k[0].GetBytes(1) {
      return data
   }
   return nil
}

func (k KeyContainer) iv() []byte {
   for data := range k[0].GetBytes(2) {
      return data
   }
   return nil
}

func (r ResponseBody) session_key() []byte {
   for data := range r[0].GetBytes(4) {
      return data
   }
   return nil
}

func (r ResponseBody) Container() iter.Seq[KeyContainer] {
   return func(yield func(KeyContainer) bool) {
      for data := range r[0].Get(2) {
         for data := range data.Get(3) {
            if !yield(KeyContainer{data}) {
               return
            }
         }
      }
   }
}
