package widevine

import (
   "encoding/base64"
   "fmt"
   "net/http"
   "os"
   "testing"
)

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
   pssh, err := base64.StdEncoding.DecodeString(tests[1].pssh)
   if err != nil {
      t.Fatal(err)
   }
   var module CDM
   if err := module.New(private_key, client_id, pssh); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
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

func (roku) Request_URL() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0cDfgumdXKcqcMrvOvQx6CVdZUyuggi6UUg3CgGcxXZjmjufQl_UfdFaoLYkos6eWWa5HUZpVls3J--WyclvOaeFHFQ9kfZCMSOFfTPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIwtbHTR_i_2GIrUmU1emdMEV6F74R&traceId=4dfb5854e7aa57513f8ee9e9c785dcbb&ExpressPlayToken=none", true
}
