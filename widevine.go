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

type Cdm struct {
   license_request []byte
   private_key *rsa.PrivateKey
}

func (c *Cdm) New(private_key, client_id, pssh []byte) error {
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

func (c *Cdm) Block(message SignedMessage) (cipher.Block, error) {
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, c.private_key, message.session_key(), nil,
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
   signed := protobuf.Message{}
   // kktv.me
   // type: LICENSE_REQUEST
   signed.AddVarint(1, 1)
   signed.AddBytes(2, c.license_request)
   signed.AddBytes(3, signature)
   return signed.Marshal(), nil
}

func (p *PsshData) Marshal() []byte {
   message := protobuf.Message{}
   if p.KeyId != nil {
      message.AddBytes(2, p.KeyId)
   }
   if p.ContentId != nil {
      message.AddBytes(4, p.ContentId)
   }
   return message.Marshal()
}

type PsshData struct {
   ContentId []byte
   KeyId []byte
}

func (k KeyContainer) Decrypt(block cipher.Block) []byte {
   key := k.key()
   cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(key, key)
   return unpad(key)
}

func (k KeyContainer) Id() []byte {
   value, _ := k.message.GetBytes(1)()
   return value
}

func (k KeyContainer) iv() []byte {
   value, _ := k.message.GetBytes(2)()
   return value
}

func (k KeyContainer) key() []byte {
   value, _ := k.message.GetBytes(3)()
   return value
}

type KeyContainer struct {
   message protobuf.Message
}

func (l License) Container() func() (KeyContainer, bool) {
   values := l.message.Get(3)
   return func() (KeyContainer, bool) {
      value, ok := values()
      return KeyContainer{value}, ok
   }
}

type License struct {
   message protobuf.Message
}

type rand struct{}

func (rand) Read(b []byte) (int, error) {
   return len(b), nil
}

func (s *SignedMessage) Unmarshal(data []byte) error {
   s.message = protobuf.Message{}
   return s.message.Unmarshal(data)
}

func (s SignedMessage) License() License {
   value, _ := s.message.Get(2)()
   return License{value}
}

type SignedMessage struct {
   message protobuf.Message
}

func (s SignedMessage) session_key() []byte {
   value, _ := s.message.GetBytes(4)()
   return value
}
