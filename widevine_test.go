package widevine

import (
   "bytes"
   "encoding/base64"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestCdm1(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   var cdm0 Cdm
   err = cdm0.New(private_key, nil, nil)
   if err != nil {
      t.Fatal(err)
   }
   _, err = cdm0.Block(ResponseBody{})
   if err == nil {
      t.Fatal("Cdm.Block")
   }
}

var ctv_ca = struct{
   content_id string
   key string
   key_id string
   url string
}{
   content_id: "ZmYtOGYyNjEzYWUtNTIxNTAx",
   key: "xQ87t+z5cLOVgxDdSgHyoA==",
   key_id: "A98dtspZsb9/z++3IHp0Dw==",
   url: "ctv.ca/movies/fools-rush-in-57470",
}

func TestCdm0(t *testing.T) {
   key, err := base64.StdEncoding.DecodeString(ctv_ca.key)
   if err != nil {
      t.Fatal(err)
   }
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
   key_id, err := base64.StdEncoding.DecodeString(ctv_ca.key_id)
   if err != nil {
      t.Fatal(err)
   }
   var pssh0 Pssh
   pssh0.KeyIds = [][]byte{key_id}
   pssh0.ContentId, err = base64.StdEncoding.DecodeString(ctv_ca.content_id)
   if err != nil {
      t.Fatal(err)
   }
   var cdm0 Cdm
   err = cdm0.New(private_key, client_id, pssh0.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   data, err := cdm0.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   resp, err := ctv_service(data)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      t.Fatal(resp.Status)
   }
   var body ResponseBody
   err = body.Unmarshal(data)
   if err != nil {
      t.Fatal(err)
   }
   block, err := cdm0.Block(body)
   if err != nil {
      t.Fatal(err)
   }
   next := body.Container()
   for {
      container, ok := next()
      if !ok {
         break
      }
      if bytes.Equal(container.Id(), key_id) {
         if bytes.Equal(container.Key(block), key) {
            return
         }
      }
   }
   t.Fatal("key not found")
}

func ctv_service(data []byte) (*http.Response, error) {
   return http.Post(
      "https://license.9c9media.ca/widevine", "application/x-protobuf",
      bytes.NewReader(data),
   )
}
