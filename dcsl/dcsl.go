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
   "strconv"
)

func main() {
   http.DefaultClient.Transport = transport{}
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
   log.Print(req.URL)
   return http.DefaultTransport.RoundTrip(req)
}

func (g *get_license) String() string {
   b := []byte("client max hdcp version = ")
   b = append(b, g.ClientMaxHdcpVersion...)
   b = append(b, "\ninternal status = "...)
   b = strconv.AppendInt(b, g.InternalStatus, 10)
   b = append(b, "\nmake = "...)
   b = append(b, g.Make...)
   b = append(b, "\nmodel = "...)
   b = append(b, g.Model...)
   b = append(b, "\noem crypto api version = "...)
   b = strconv.AppendInt(b, g.OemCryptoApiVersion, 10)
   b = append(b, "\nplatform = "...)
   b = append(b, g.Platform...)
   b = append(b, "\nsecurity level = "...)
   b = strconv.AppendInt(b, g.SecurityLevel, 10)
   b = append(b, "\nsoc = "...)
   b = append(b, g.Soc...)
   b = append(b, "\nstatus = "...)
   b = append(b, g.Status...)
   if g.StatusMessage != "" {
      b = append(b, "\nstatus message = "...)
      b = append(b, g.StatusMessage...)
   }
   b = append(b, "\nsystem id = "...)
   b = strconv.AppendInt(b, g.SystemId, 10)
   return string(b)
}

type get_license struct {
   ClientMaxHdcpVersion string `json:"client_max_hdcp_version"`
   InternalStatus       int64  `json:"internal_status"`
   Make                 string
   Model                string
   OemCryptoApiVersion  int64 `json:"oem_crypto_api_version"`
   Platform             string
   SecurityLevel        int64 `json:"security_level"`
   Soc                  string
   Status               string
   StatusMessage        string `json:"status_message"`
   SystemId             int64  `json:"system_id"`
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
