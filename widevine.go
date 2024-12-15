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

func (s *signed_message) unmarshal(data []byte) error {
   s.Message = protobuf.Message{}
   return s.Message.Unmarshal(data)
}

func (s signed_message) license() license {
   value, _ := s.Message.Get(2)()
   return license{value}
}

func (l license) key_container() func() (key_container, bool) {
   values := l.Message.Get(3)
   return func() (key_container, bool) {
      value, ok := values()
      return key_container{value}, ok
   }
}

func (k key_container) id() []byte {
   value, _ := k.Message.GetBytes(1)()
   return value
}

func (k key_container) iv() []byte {
   value, _ := k.Message.GetBytes(2)()
   return value
}

func (k key_container) key() []byte {
   value, _ := k.Message.GetBytes(3)()
   return value
}

type signed_message struct {
   Message protobuf.Message
}

type license struct {
   Message protobuf.Message
}

func (s signed_message) session_key() []byte {
   value, _ := s.Message.GetBytes(4)()
   return value
}

func request_body(private_key, client_id, pssh []byte) ([]byte, error) {
   block, _ := pem.Decode(private_key)
   private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   license_request := protobuf.Message{
      1: {protobuf.Bytes(client_id)},
      2: {protobuf.Message{ // content_id
         1: {protobuf.Message{ // widevine_pssh_data
            1: {protobuf.Bytes(pssh)},
         }},
      }},
   }.Marshal()
   hash := sha1.Sum(license_request)
   signature, err := rsa.SignPSS(
      no_operation{},
      private,
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
   signed.AddBytes(2, license_request)
   signed.AddBytes(3, signature)
   return signed.Marshal(), nil
}

func (s signed_message) block(
   private_key, client_id, pssh []byte,
) (cipher.Block, error) {
   block, _ := pem.Decode(private_key)
   private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   license_request := protobuf.Message{
      1: {protobuf.Bytes(client_id)},
      2: {protobuf.Message{ // content_id
         1: {protobuf.Message{ // widevine_pssh_data
            1: {protobuf.Bytes(pssh)},
         }},
      }},
   }.Marshal()
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, private, s.session_key(), nil,
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
   data = append(data, license_request...)
   data = append(data, 0, 0, 0, 128) // hash.Size()
   if _, err = hash.Write(data); err != nil {
      return nil, err
   }
   return aes.NewCipher(hash.Sum(nil))
}

type key_container struct {
   Message protobuf.Message
}

func (k key_container) decrypt(block cipher.Block) []byte {
   key := k.key()
   cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(key, key)
   return unpad(key)
}

type no_operation struct{}

func (no_operation) Read(b []byte) (int, error) {
   return len(b), nil
}

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
