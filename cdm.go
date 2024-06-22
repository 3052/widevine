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
   "io"
   "net/http"
)

func (c CDM) decrypt(license_response, key_id []byte) ([]byte, error) {
   var message protobuf.Message // SignedMessage
   err := message.Consume(license_response)
   if err != nil {
      return nil, err
   }
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, c.private_key, <-message.GetBytes(4), nil,
   )
   if err != nil {
      return nil, err
   }
   var text []byte
   text = append(text, 1)
   text = append(text, "ENCRYPTION"...)
   text = append(text, 0)
   text = append(text, c.license_request...)
   text = append(text, 0, 0, 0, 0x80)
   hash, err := cmac.New(aes.NewCipher, session_key)
   if err != nil {
      return nil, err
   }
   _, err = hash.Write(text)
   if err != nil {
      return nil, err
   }
   block, err := aes.NewCipher(hash.Sum(nil))
   if err != nil {
      return nil, err
   }
   // this is listed as: optional bytes msg = 2;
   // but assuming the type is: LICENSE = 2;
   // the result is actually: optional License msg = 2;
   license := <-message.Get(2)
   for container := range license.Get(3) { // KeyContainer key
      // this field is: optional bytes id = 1;
      // but CONTENT keys should always have it
      id, ok := <-container.GetBytes(1)
      if !ok {
         continue
      }
      if !bytes.Equal(id, key_id) {
         continue
      }
      iv, ok := <-container.GetBytes(2)
      if !ok {
         continue
      }
      key, ok := <-container.GetBytes(3)
      if !ok {
         continue
      }
      cipher.NewCBCDecrypter(block, iv).CryptBlocks(key, key)
      return unpad(key), nil
   }
   return nil, errors.New("CDM.decrypt")
}

func (c CDM) sign_request() ([]byte, error) {
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
   // SignedMessage
   var signed protobuf.Message
   // kktv.me
   // type: LICENSE_REQUEST
   signed.AddVarint(1, 1)
   signed.AddBytes(2, c.license_request)
   signed.AddBytes(3, signature)
   return signed.Encode(), nil
}

type CDM struct {
   license_request []byte
   private_key *rsa.PrivateKey
}

func (c CDM) Key(post Poster, key_id []byte) ([]byte, error) {
   address, ok := post.RequestUrl()
   if !ok {
      return nil, errors.New("Poster.RequestUrl")
   }
   signed_request, err := c.sign_request()
   if err != nil {
      return nil, err
   }
   wrapped_request, err := post.WrapRequest(signed_request)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", address, bytes.NewReader(wrapped_request))
   if err != nil {
      return nil, err
   }
   req.Header, err = post.RequestHeader()
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
   license_response, err := post.UnwrapResponse(wrapped_response)
   if err != nil {
      return nil, err
   }
   return c.decrypt(license_response, key_id)
}

func (c *CDM) New(private_key, client_id, pssh []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return err
   }
   var request protobuf.Message               // LicenseRequest
   request.AddBytes(1, client_id)             // client_id
   request.Add(2, func(m *protobuf.Message) { // content_id
      m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddBytes(1, pssh)
      })
   })
   c.license_request = request.Encode()
   return nil
}
