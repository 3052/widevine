package main

import (
   "bytes"
   "encoding/json"
   "io"
   "net/http"
)

func (wrapper) Wrap(data []byte) ([]byte, error) {
   var err error
   data, err = json.Marshal(map[string][]byte{
      "payload": data,
   })
   if err != nil {
      return nil, err
   }
   data, err = json.Marshal(map[string]any{
      "request": data,
      "signer": "widevine_test",
   })
   if err != nil {
      return nil, err
   }
   resp, err := http.Post(
      "https://license.uat.widevine.com/cenc/getlicense", "",
      bytes.NewReader(data),
   )
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}
