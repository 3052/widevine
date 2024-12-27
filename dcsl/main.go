package main

import (
   "flag"
   "fmt"
   "net/http"
   "os"
)

type transport struct{}

func (transport) RoundTrip(req *http.Request) (*http.Response, error) {
   fmt.Println(req.URL)
   return http.DefaultTransport.RoundTrip(req)
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
