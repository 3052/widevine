package widevine

import (
   "bytes"
   "encoding/base64"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestCdmRequestBody(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   key_id, err := base64.StdEncoding.DecodeString(pluto_tv.key_id)
   if err != nil {
      t.Fatal(err)
   }
   var pssh0 Pssh
   pssh0.KeyIds = [][]byte{key_id}
   var cdm0 Cdm
   err = cdm0.New(private_key, client_id, pssh0.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   data, err := cdm0.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   resp, err := pluto_service(data)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   _, err = io.Copy(io.Discard, resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      t.Fatal(resp.Status)
   }
}

func pluto_service(data []byte) (*http.Response, error) {
   return http.Post(
      "https://service-concierge.clusters.pluto.tv/v1/wv/alt",
      "application/x-protobuf", bytes.NewReader(data),
   )
}

var pluto_tv = struct{
   key_id string
   url    string
}{
   key_id: "AAAAAGbZBRrrxvnmpuNLhg==",
   url:    "pluto.tv/us/on-demand/movies/5c4bb2b308d10f9a25bbc6af",
}
