package main

import (
   "41.neocities.org/widevine"
   "flag"
   "fmt"
   "net/http"
   "os"
)

// demo.unified-streaming.com/k8s/features
const content_id = "fkj3ljaSdfalkr3j"

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
      data, err := post(private_key, client_id)
      if err != nil {
         panic(err)
      }
      os.Stdout.Write(data)
   } else {
      flag.Usage()
   }
}

type transport struct{}

func (transport) RoundTrip(req *http.Request) (*http.Response, error) {
   fmt.Println(req.URL)
   return http.DefaultTransport.RoundTrip(req)
}

type wrapper struct{}

func post(private_key, client_id []byte) ([]byte, error) {
   var pssh widevine.PsshData
   pssh.ContentId = []byte(content_id)
   var module widevine.Cdm
   err := module.New(private_key, client_id, pssh.Marshal())
   if err != nil {
      return nil, err
   }
   data, err := module.RequestBody()
   if err != nil {
      return nil, err
   }
   return wrapper{}.Wrap(data)
}
