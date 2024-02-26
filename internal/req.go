package main

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "encoding/pem"
   "errors"
   "fmt"
   "github.com/chmike/cmac-go"
   "io"
   "log/slog"
   "net/http"
   "net/url"
   "strings"
)

func main() {
   var req http.Request
   req.Header = make(http.Header)
   req.Header["Accept"] = []string{"*/*"}
   req.Header["Connection"] = []string{"keep-alive"}
   req.Header["Host"] = []string{"ovp.peacocktv.com"}
   req.Header["User-Agent"] = []string{"python-requests/2.31.0"}
   req.Method = "POST"
   req.ProtoMajor = 1
   req.ProtoMinor = 1
   req.URL = new(url.URL)
   req.URL.Host = "ovp.peacocktv.com"
   req.URL.Path = "/drm/widevine/acquirelicense"
   val := make(url.Values)
   val["bt"] = []string{"99-kmZraEntWbWr6LmEF_KJP3x8sZk2JDFFYwjjYRlrBaK8lKzgFJ0vId2jmQ0QMFCzVcAxESCKdL5elK63DBe5dNJwCoYYk3T1wh0_ClN6M-EGKmy6uPgjwWRhfrZWmhlmMKyiq9JQxV54-UGkG6Yne0S4U9TYtbN6tX3_sobqET3BO2J2Ux0Z1x1Z985UaaNJEydmji_GZr6Eb3LizYYCnHOg03_MAvGtE0WlCyOtIy8VQrmuT7j_dvr7-JdOWXQwDzi-Th-84Z4P-yUcOtti4bFWuxrMSfpimlnUqLRyPTQsYqHAJUpUN_9kaqwvlxFfLGxzYlY_b75k-RgUq86VwKzbbGMQTF8qJ46faR_gJModrStHS__wfvYwh0FjjygzouTmK1mt1-K6ZXhn"}
   req.URL.RawQuery = val.Encode()
   req.URL.Scheme = "https"
   req.Body = io.NopCloser(bytes.NewReader(message.Encode()))
   res, err := new(http.Transport).RoundTrip(&req)
   if err != nil {
      panic(err)
   }
   defer res.Body.Close()
   var b strings.Builder
   res.Write(&b)
   fmt.Printf("%q\n", b.String())
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

func request_signed() ([]byte, error) {
   block, _ := pem.Decode(private_key)
   var err error
   module.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   var request protobuf.Message // LicenseRequest
   request.AddBytes(1, client_id) // client_id
   request.AddFunc(2, func(m *protobuf.Message) { // content_id
      m.AddFunc(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddFunc(1, func(m *protobuf.Message) { // pssh_data
            m.AddBytes(2, p.Key_ID)
            m.AddBytes(4, p.content_id)
         })
      })
   })
   module.license_request = request.Encode()
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
