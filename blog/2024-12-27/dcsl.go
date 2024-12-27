package main

import (
   "41.neocities.org/widevine"
   "bytes"
   "encoding/json"
   "net/http"
)

/*
L1-pass
*/
type get_license struct {
   Status string
   StatusMessage string `json:"status_message"`
   Make string
   Model string
   SecurityLevel int `json:"security_level"`
   InternalStatus int `json:"internal_status"`
   ClientMaxHdcpVersion string `json:"client_max_hdcp_version"`
   Platform string
   Soc string
   SystemId int `json:"system_id"`
}

func (g *get_license) New(private_key, client_id []byte) error {
   var pssh widevine.PsshData
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
      "signer": "widevine_test",
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
