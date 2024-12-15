package widevine

import (
   "41.neocities.org/protobuf"
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
   "io"
   "net/http"
)

// go.dev/pkg/net/http?m=old#Client.Do
func one(*http.Request) (*http.Response, error) {
   return nil, nil
}

func zero(private_key, client_id, pssh []byte) ([]byte, error) {
   return nil, nil
}

type signed_message struct{}

func (m *Module) decrypt(license_response, key_id []byte) ([]byte, error) {
   message := protobuf.Message{} // SignedMessage
   err := message.Unmarshal(license_response)
   if err != nil {
      return nil, err
   }
   session_key, ok := message.GetBytes(4)()
   if !ok {
      return nil, errors.New("session_key")
   }
   session_key, err = rsa.DecryptOAEP(
      sha1.New(), nil, m.private_key, session_key, nil,
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
   data = append(data, m.license_request...)
   data = append(data, 0, 0, 0, 128) // hash.Size()
   if _, err = hash.Write(data); err != nil {
      return nil, err
   }
   block, err := aes.NewCipher(hash.Sum(nil))
   if err != nil {
      return nil, err
   }
   // this is listed as: optional bytes msg = 2;
   // but assuming the type is: LICENSE = 2;
   // the result is actually: optional License msg = 2;
   license, ok := message.Get(2)()
   if !ok {
      return nil, errors.New("license")
   }
   containers := license.Get(3) // KeyContainer key
   for {
      container, ok := containers()
      if !ok {
         return nil, errors.New("KeyContainer")
      }
      // this field is: optional bytes id = 1;
      // but CONTENT keys should always have it
      id, ok := container.GetBytes(1)()
      if !ok {
         continue
      }
      if !bytes.Equal(id, key_id) {
         continue
      }
      iv, ok := container.GetBytes(2)()
      if !ok {
         continue
      }
      key, ok := container.GetBytes(3)()
      if !ok {
         continue
      }
      cipher.NewCBCDecrypter(block, iv).CryptBlocks(key, key)
      return unpad(key), nil
   }
}
func (m *Module) sign_request() ([]byte, error) {
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
   // SignedMessage
   signed := protobuf.Message{}
   // kktv.me
   // type: LICENSE_REQUEST
   signed.AddVarint(1, 1)
   signed.AddBytes(2, m.license_request)
   signed.AddBytes(3, signature)
   return signed.Marshal(), nil
}

type Client interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   WrapRequest([]byte) ([]byte, error)
   UnwrapResponse([]byte) ([]byte, error)
}

func (m *Module) Key(c Client, key_id []byte) ([]byte, error) {
   address, ok := c.RequestUrl()
   if !ok {
      return nil, errors.New("Client.RequestUrl")
   }
   signed_request, err := m.sign_request()
   if err != nil {
      return nil, err
   }
   wrapped_request, err := c.WrapRequest(signed_request)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", address, bytes.NewReader(wrapped_request))
   if err != nil {
      return nil, err
   }
   req.Header, err = c.RequestHeader()
   if err != nil {
      return nil, err
   }
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      var b bytes.Buffer
      resp.Write(&b)
      return nil, errors.New(b.String())
   }
   wrapped_response, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   license_response, err := c.UnwrapResponse(wrapped_response)
   if err != nil {
      return nil, err
   }
   return m.decrypt(license_response, key_id)
}

func (m *Module) New(private_key, client_id, pssh []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   m.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   m.license_request = protobuf.Message{
      1: {protobuf.Bytes(client_id)},
      2: {protobuf.Message{ // content_id
         1: {protobuf.Message{ // widevine_pssh_data
            1: {protobuf.Bytes(pssh)},
         }},
      }},
   }.Marshal()
   return nil
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

type Module struct {
   license_request []byte
   private_key *rsa.PrivateKey
}
