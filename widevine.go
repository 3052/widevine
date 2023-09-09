package widevine

import (
   "154.pages.dev/encoding/protobuf"
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "github.com/chmike/cmac-go"
   "io"
   "net/http"
)

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
// some videos require key_id and content_id, so entire PSSH is needed
func New_Module(private_key, client_ID, pssh []byte) (*Module, error) {
   block, _ := pem.Decode(private_key)
   var (
      err error
      mod Module
   )
   mod.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   var m protobuf.Message
   m.Add_Bytes(1, client_ID)
   m.Add(2, func(m *protobuf.Message) { // ContentId
      m.Add(1, func(m *protobuf.Message) { // CencId
         m.Add_Bytes(1, pssh[32:])
      })
   })
   mod.license_request = m.Append(nil)
   return &mod, nil
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

type Module struct {
   license_request []byte
   private_key *rsa.PrivateKey
}

func (m Module) Post(post Poster) (Containers, error) {
   signed_request, err := m.signed_request()
   if err != nil {
      return nil, err
   }
   body, err := post.Request_Body(signed_request)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", post.Request_URL(), bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   if head := post.Request_Header(); head != nil {
      req.Header = head
   }
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   body, err = io.ReadAll(res.Body)
   if err != nil {
      return nil, err
   }
   body, err = post.Response_Body(body)
   if err != nil {
      return nil, err
   }
   return m.signed_response(body)
}

type Poster interface {
   Request_URL() string
   Request_Header() http.Header
   Request_Body([]byte) ([]byte, error)
   Response_Body([]byte) ([]byte, error)
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

