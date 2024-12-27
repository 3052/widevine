package main

import (
   "encoding/json"
   "flag"
   "fmt"
   "net/http"
   "os"
)

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
      var license get_license
      err = license.New(private_key, client_id)
      if err != nil {
         panic(err)
      }
      encode := json.NewEncoder(os.Stdout)
      encode.SetIndent("", " ")
      err = encode.Encode(license)
      if err != nil {
         panic(err)
      }
   } else {
      flag.Usage()
   }
}

// demo.unified-streaming.com/k8s/features
const content_id = "fkj3ljaSdfalkr3j"

type transport struct{}

func (transport) RoundTrip(req *http.Request) (*http.Response, error) {
   fmt.Println(req.URL)
   return http.DefaultTransport.RoundTrip(req)
}
