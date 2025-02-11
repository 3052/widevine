package widevine

import (
   "41.neocities.org/widevine"
   "bytes"
   "encoding/base64"
   "fmt"
   "os"
   "testing"
)

func Test(t *testing.T) {
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
   key_id, err := base64.StdEncoding.DecodeString(video_test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   var pssh widevine.PsshData
   pssh.KeyIds = [][]byte{key_id}
   var module widevine.Cdm
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   data, err := module.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   data, err = Wrapper{}.Wrap(data)
   if err != nil {
      t.Fatal(err)
   }
   var body widevine.ResponseBody
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
      if bytes.Equal(container.Id(), key_id) {
         fmt.Printf("%x\n", container.Key(block))
      }
   }
}


// the slug is useful as it sometimes contains the year, but its not worth
// parsing since its sometimes missing
var video_test = struct{
   id     string
   key_id string
   url    string
}{
   id:     "5c4bb2b308d10f9a25bbc6af",
   key_id: "AAAAAGbZBRrrxvnmpuNLhg==",
   url:    "pluto.tv/us/on-demand/movies/5c4bb2b308d10f9a25bbc6af",
}
