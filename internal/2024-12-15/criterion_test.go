package criterion

import (
   "41.neocities.org/widevine"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "net/http"
   "fmt"
   "os"
   "testing"
)

func (client) WrapRequest(b []byte) ([]byte, error) {
   return b, nil
}

func (client) UnwrapResponse(b []byte) ([]byte, error) {
   var value struct {
      License []byte
   }
   err := json.Unmarshal(b, &value)
   if err != nil {
      return nil, err
   }
   return value.License, nil
}

type client struct{}

func (client) RequestUrl() (string, bool) {
   return "https://lic.staging.drmtoday.com/license-proxy-widevine/cenc", true
}

func (client) RequestHeader() (http.Header, error) {
   data, err := json.Marshal(map[string]string{
      "merchant": "client_dev",
      "userId":   "purchase",
   })
   if err != nil {
      return nil, err
   }
   return http.Header{
      "dt-custom-data": {base64.StdEncoding.EncodeToString(data)},
   }, nil
}

func TestLicense(t *testing.T) {
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
   var pssh widevine.Pssh
   pssh.KeyId, err = hex.DecodeString(key_id)
   if err != nil {
      t.Fatal(err)
   }
   var module widevine.Module
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(client{}, pssh.KeyId)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

// content.players.castlabs.com/demos/drm-agent/manifest.mpd
const key_id = "6f6b1b9884f83d0b866a1bd8aca390d2"
