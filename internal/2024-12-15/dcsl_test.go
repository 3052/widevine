package dcsl

import (
   "41.neocities.org/widevine"
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "net/http"
   "os"
   "testing"
)

// content.players.castlabs.com/demos/drm-agent/manifest.mpd
const key_id = "6f6b1b9884f83d0b866a1bd8aca390d2"

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
   var pssh widevine.PsshData
   pssh.KeyId, err = hex.DecodeString(key_id)
   if err != nil {
      t.Fatal(err)
   }
   var module widevine.Cdm
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      t.Fatal(err)
   }
   data, err := module.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   req, err := http.NewRequest(
      "POST", "https://lic.staging.drmtoday.com/license-proxy-widevine/cenc",
      bytes.NewReader(data),
   )
   if err != nil {
      t.Fatal(err)
   }
   data, err = json.Marshal(map[string]string{
      "merchant": "client_dev",
      "userId":   "purchase",
   })
   if err != nil {
      t.Fatal(err)
   }
   req.Header.Set("dt-custom-data", base64.StdEncoding.EncodeToString(data))
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   resp.Write(os.Stdout)
}
