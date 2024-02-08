package widevine

import (
   "encoding/base64"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func Test_Response(t *testing.T) {
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
   for _, test := range tests {
      protect := func() (p Pssh) {
         b, err := base64.StdEncoding.DecodeString(test.pssh)
         if err != nil {
            t.Fatal(err)
         }
         if err := p.New(b); err != nil {
            t.Fatal(err)
         }
         return
      }()
      signed, err := base64.StdEncoding.DecodeString(test.response)
      if err != nil {
         t.Fatal(err)
      }
      module, err := protect.Cdm(private_key, client_id)
      if err != nil {
         t.Fatal(err)
      }
      license, err := module.response(signed)
      if err != nil {
         t.Fatal(err)
      }
      key, ok := module.Key(license)
      if !ok {
         t.Fatal("Cdm.Key")
      }
      fmt.Println(test.url)
      fmt.Printf("%x\n\n", key)
   }
}

func Test_Roku(t *testing.T) {
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
   // PSSH
   protect := func() (p Pssh) {
      b, err := base64.StdEncoding.DecodeString(tests[1].pssh)
      if err != nil {
         t.Fatal(err)
      }
      if err := p.New(b); err != nil {
         t.Fatal(err)
      }
      return
   }()
   
   
   
   
   signed, err := base64.StdEncoding.DecodeString(test.response)
   if err != nil {
      t.Fatal(err)
   }
   module, err := protect.Cdm(private_key, client_id)
   if err != nil {
      t.Fatal(err)
   }
   license, err := module.response(signed)
   if err != nil {
      t.Fatal(err)
   }
   key, ok := module.Key(license)
   if !ok {
      t.Fatal("Cdm.Key")
   }
   fmt.Println(test.url)
   fmt.Printf("%x\n\n", key)
   
   
   
   var module Cdm
   if err := module.New(private_key); err != nil {
      t.Fatal(err)
   }
   if err := module.PSSH(client_id, pssh); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func (roku) Request_URL() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1LWqkvntCYIqcO-fiqQx7VVt1Ukewk36UWgiT0T8tTY2jxsKAl_RKOQPlfbE0ourfEPpWGYpAwsH0qrmGdyvWUeVzARN9KZCMSD0DUPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMI9avATR8m2oNk3tm5aXtW1GWjh5kS&traceId=a731a6206e341e14fe7124dee998add7&ExpressPlayToken=none", true
}

func (roku) Request_Header() (http.Header, bool) {
   return nil, false
}

type roku struct{}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}
