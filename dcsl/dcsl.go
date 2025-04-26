package main

import (
   "41.neocities.org/widevine"
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "log"
   "net/http"
   "os"
)

func main() {
   http.DefaultClient.Transport = transport{}
   log.SetFlags(log.Ltime)
   var client_id struct {
      data []byte
      name string
   }
   var private_key struct {
      data []byte
      name string
   }
   flag.StringVar(&client_id.name, "c", "", "client ID")
   flag.StringVar(&private_key.name, "p", "", "private key")
   flag.Parse()
   if client_id.name != "" {
      var err error
      client_id.data, err = os.ReadFile(client_id.name)
      if err != nil {
         panic(err)
      }
      private_key.data, err = os.ReadFile(private_key.name)
      if err != nil {
         panic(err)
      }
      var license get_license
      err = license.New(private_key.data, client_id.data)
      if err != nil {
         panic(err)
      }
      fmt.Println(&license)
   } else {
      flag.Usage()
   }
}

type transport struct{}

func (transport) RoundTrip(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultTransport.RoundTrip(req)
}

// demo.unified-streaming.com/k8s/features
const content_id = "fkj3ljaSdfalkr3j"

func (g *get_license) New(private_key, client_id []byte) error {
   var pssh widevine.Pssh
   pssh.ContentId = []byte(content_id)
   var module widevine.Cdm
   err := module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      return err
   }
   data, err := module.RequestBody()
   if err != nil {
      return err
   }
   data, err = json.Marshal(map[string][]byte{
      "payload": data,
   })
   if err != nil {
      return err
   }
   data, err = json.Marshal(map[string]any{
      "request": data,
      "signer":  "widevine_test",
   })
   if err != nil {
      return err
   }
   resp, err := http.Post(
      "https://license.uat.widevine.com/cenc/getlicense", "",
      bytes.NewReader(data),
   )
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   return json.NewDecoder(resp.Body).Decode(g)
}

type get_license struct {
   ClientMaxHdcpVersion string `json:"client_max_hdcp_version"`
   InternalStatus       int    `json:"internal_status"`
   Make                 string
   Model                string
   OemCryptoApiVersion  int `json:"oem_crypto_api_version"`
   Platform             string
   SecurityLevel        int `json:"security_level"`
   Soc                  string
   Status               string
   StatusMessage        string `json:"status_message"`
   SystemId             int    `json:"system_id"`
}

var line = fmt.Appendln

func (g *get_license) String() string {
   b := line(nil, "client max hdcp version =", g.ClientMaxHdcpVersion)
   b = line(b, "internal status =", g.InternalStatus)
   b = line(b, "make =", g.Make)
   b = line(b, "model =", g.Model)
   b = line(b, "oem crypto api version =", g.OemCryptoApiVersion)
   b = line(b, "platform =", g.Platform)
   b = line(b, "security level =", g.SecurityLevel)
   b = line(b, "soc =", g.Soc)
   b = line(b, "status =", g.Status)
   if g.StatusMessage != "" {
      b = line(b, "status message =", g.StatusMessage)
   }
   b = fmt.Append(b, "system id = ", g.SystemId)
   return string(b)
}
