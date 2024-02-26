package main

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "os"
   "strings"
)

func main() {
   return
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
   data, err := request_signed(message.Encode())
   if err != nil {
      panic(err)
   }
   req.Body = io.NopCloser(bytes.NewReader(data))
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

func request_signed(message []byte) ([]byte, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   home += "/widevine/"
   raw_private_key, err := os.ReadFile(home + "private_key.pem")
   if err != nil {
      return nil, err
   }
   block, _ := pem.Decode(raw_private_key)
   private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   hash := sha1.Sum(message)
   signature, err := rsa.SignPSS(
      no_operation{},
      private_key,
      crypto.SHA1,
      hash[:],
      &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
   )
   if err != nil {
      return nil, err
   }
   var signed protobuf.Message // SignedMessage
   signed.AddBytes(2, message)
   signed.AddBytes(3, signature)
   return signed.Encode(), nil
}
