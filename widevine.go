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
)

func unpad(b []byte) []byte {
   if len(b) >= 1 {
      pad := b[len(b)-1]
      if len(b) >= int(pad) {
         b = b[:len(b)-int(pad)]
      }
   }
   return b
}

type Pssh struct {
   ContentId []byte
   KeyId []byte
}

func (p Pssh) Marshal() []byte {
   message := protobuf.Message{}
   if p.KeyId != nil {
      message.AddBytes(2, p.KeyId)
   }
   if p.ContentId != nil {
      message.AddBytes(4, p.ContentId)
   }
   return message.Marshal()
}

func (c *client) New(private_key, client_id, pssh []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   c.license_request = protobuf.Message{
      1: {protobuf.Bytes(client_id)},
      2: {protobuf.Message{ // content_id
         1: {protobuf.Message{ // widevine_pssh_data
            1: {protobuf.Bytes(pssh)},
         }},
      }},
   }.Marshal()
   return nil
}

type client struct {
   license_request []byte
   private_key *rsa.PrivateKey
}

func (c *client) block(session_key []byte) (cipher.Block, error) {
   var err error
   session_key, err = rsa.DecryptOAEP(
      sha1.New(), nil, c.private_key, session_key, nil,
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
   data = append(data, 0, 0, 0, 128) // hash.Size()
   _, err = hash.Write(data)
   if err != nil {
      return nil, err
   }
   return aes.NewCipher(hash.Sum(nil))
}

func (c *client) request_body(client_id, pssh []byte) ([]byte, error) {
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
   signed := protobuf.Message{}
   // kktv.me
   // type: LICENSE_REQUEST
   signed.AddVarint(1, 1)
   signed.AddBytes(2, c.license_request)
   signed.AddBytes(3, signature)
   return signed.Marshal(), nil
}

func (k key_container) decrypt(block cipher.Block) []byte {
   key := k.key()
   cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(key, key)
   return unpad(key)
}

func (k key_container) id() []byte {
   value, _ := k.message.GetBytes(1)()
   return value
}

func (k key_container) iv() []byte {
   value, _ := k.message.GetBytes(2)()
   return value
}

func (k key_container) key() []byte {
   value, _ := k.message.GetBytes(3)()
   return value
}

type key_container struct {
   message protobuf.Message
}

func (l license) key_container() func() (key_container, bool) {
   values := l.message.Get(3)
   return func() (key_container, bool) {
      value, ok := values()
      return key_container{value}, ok
   }
}

type license struct {
   message protobuf.Message
}

type rand struct{}

func (rand) Read(b []byte) (int, error) {
   return len(b), nil
}

func (s *signed_message) unmarshal(data []byte) error {
   s.message = protobuf.Message{}
   return s.message.Unmarshal(data)
}

func (s signed_message) license() license {
   value, _ := s.message.Get(2)()
   return license{value}
}

type signed_message struct {
   message protobuf.Message
}

func (s signed_message) session_key() []byte {
   value, _ := s.message.GetBytes(4)()
   return value
}
