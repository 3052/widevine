package widevine

import (
   "bytes"
   "encoding/base64"
   "fmt"
   "io"
   "net/http"
   "os"
   "testing"
)

var test = struct{
   id     string
   key_id string
   url    string
}{
   id:     "675a0fa22678a50014690c3f",
   key_id: "AAAAAGdaD6FuwTSRB/+yHg==",
   url:    "pluto.tv/on-demand/movies/675a0fa22678a50014690c3f",
}

func TestPluto(t *testing.T) {
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
   var pssh PsshData
   pssh.KeyId, err = base64.StdEncoding.DecodeString(test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   var module Cdm
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   data, err := module.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   data, err = pluto(data)
   if err != nil {
      t.Fatal(err)
   }
   var body ResponseBody
   err = body.Unmarshal(data)
   if err != nil {
      t.Fatal(err)
   }
   block, err := module.Block(body)
   if err != nil {
      t.Fatal(err)
   }
   containers := body.Container()
   for {
      container, ok := containers()
      if !ok {
         break
      }
      if bytes.Equal(container.Id(), pssh.KeyId) {
         fmt.Printf("%x\n", container.Decrypt(block))
      }
   }
}

func pluto(data []byte) ([]byte, error) {
   resp, err := http.Post(
      "https://service-concierge.clusters.pluto.tv/v1/wv/alt", "",
      bytes.NewReader(data),
   )
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}
