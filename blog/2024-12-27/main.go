package main

import (
   "41.neocities.org/widevine"
   "encoding/base64"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "os"
   "strings"
)

func main() {
   home, err := os.UserHomeDir()
   if err != nil {
      panic(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      panic(err)
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      panic(err)
   }
   var pssh widevine.PsshData
   pssh.ContentId, err = base64.StdEncoding.DecodeString(
      "ZmtqM2xqYVNkZmFsa3Izag==",
   )
   if err != nil {
      panic(err)
   }
   var module widevine.Cdm
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      panic(err)
   }
   data, err := module.RequestBody()
   if err != nil {
      panic(err)
   }
   var req http.Request
   req.Header = http.Header{}
   req.Method = "POST"
   req.URL = &url.URL{}
   req.URL.Host = "license.uat.widevine.com"
   req.URL.Path = "/cenc/getlicense"
   req.URL.Scheme = "https"
   text := base64.StdEncoding.EncodeToString(data)
   text = fmt.Sprintf(`
   {
     "allowed_track_types": "SD_UHD1",
     "content_id": "ZmtqM2xqYVNkZmFsa3Izag==",
     "payload": %q,
     "provider": "widevine_test"
   }
   `, text)
   text = base64.StdEncoding.EncodeToString([]byte(text))
   text = fmt.Sprintf(`
   {
      "request": %q,
      "signer": "widevine_test"
   }
   `, text)
   req.Body = io.NopCloser(strings.NewReader(text))
   resp, err := http.DefaultClient.Do(&req)
   if err != nil {
      panic(err)
   }
   defer resp.Body.Close()
   resp.Write(os.Stdout)
}
