package main

import (
   "41.neocities.org/widevine"
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "flag"
   "fmt"
   "net/http"
   "os"
   "strconv"
)

func (d *drm_today) New(private_key, client_id []byte) error {
   key_id, err := hex.DecodeString(raw_key_id)
   if err != nil {
      return err
   }
   var pssh widevine.PsshData
   pssh.KeyIds = [][]byte{key_id}
   var module widevine.Cdm
   err = module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      return err
   }
   data, err := module.RequestBody()
   if err != nil {
      return err
   }
   req, err := http.NewRequest(
      "POST", "https://lic.staging.drmtoday.com/license-proxy-widevine/cenc",
      bytes.NewReader(data),
   )
   if err != nil {
      return err
   }
   data, err = json.Marshal(map[string]string{
      "merchant": "client_dev",
      "userId":   "purchase",
   })
   if err != nil {
      return err
   }
   req.Header.Set("dt-custom-data", base64.StdEncoding.EncodeToString(data))
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   data, err = base64.StdEncoding.DecodeString(
      resp.Header.Get("x-dt-client-info"),
   )
   if err != nil {
      return err
   }
   err = json.Unmarshal(data, &d.client_info)
   if err != nil {
      return err
   }
   code, err := strconv.Atoi(resp.Header.Get("x-dt-resp-code"))
   if err != nil {
      return err
   }
   d.resp_code = resp_code(code)
   return nil
}

func main() {
   http.DefaultClient.Transport = transport{}
   var f struct {
      client_id string
      private_key string
   }
   flag.StringVar(&f.client_id, "c", "", "client ID")
   flag.StringVar(&f.private_key, "p", "", "private key")
   flag.Parse()
   if f.client_id != "" {
      client_id, err := os.ReadFile(f.client_id)
      if err != nil {
         panic(err)
      }
      private_key, err := os.ReadFile(f.private_key)
      if err != nil {
         panic(err)
      }
      var today drm_today
      err = today.New(private_key, client_id)
      if err != nil {
         panic(err)
      }
      fmt.Print(&today.client_info, "\n", today.resp_code, "\n")
   } else {
      flag.Usage()
   }
}

type drm_today struct {
   client_info client_info
   resp_code resp_code
}
