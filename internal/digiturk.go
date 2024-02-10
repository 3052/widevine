package main

import (
   "154.pages.dev/widevine"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "log/slog"
   "net/http"
   "os"
)

func main() {
   return
   module, err := new_module(digiturk_pssh, "")
   if err != nil {
      panic(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(digiturk{})
   if err != nil {
      panic(err)
   }
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

func new_module(pssh, key_id string) (*widevine.Cdm, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return nil, err
   }
   protect, err := func() (*widevine.Pssh, error) {
      var p widevine.Pssh
      if pssh != "" {
         b, err := base64.StdEncoding.DecodeString(pssh)
         if err != nil {
            return nil, err
         }
         if err := p.New(b); err != nil {
            return nil, err
         }
      } else {
         var err error
         p.Key_id, err = hex.DecodeString(key_id)
         if err != nil {
            return nil, err
         }
      }
      return &p, nil
   }()
   if err != nil {
      return nil, err
   }
   return protect.Cdm(private_key, client_id)
}

type post struct{}

func (post) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (post) ResponseBody(b []byte) ([]byte, error) {
   return b, nil
}

const digiturk_pssh = "AAAAUXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADEIARIQNQEdQ/caa7Gyyidw2vtZhBoMa3JlYWRpZ2l0dXJrIg1iZWluc3BvcnRzMDFk"

type digiturk struct {
   post
}

func (digiturk) RequestHeader() (http.Header, bool) {
   h := make(http.Header)
   h.Set("authorization", "Bearer omqQm5F7HblAKY+ixqtdqTGmifHXuLAAHj/lIwMYtyBQ3aG7mov8+fy8lyWEa4kTKkqCCAkuf6B519LPMVF2ZWC8MZLk9CtLlusXTHev+IxnxbDPw3B1Po6/ynV9IJFVMvKpCZ1nGgKRbPXB1RnLzSt/LTM=")
   h.Set("X-CB-Ticket", "b2w+gvHwCDOs2pmEwp11z69Qv6Ds6cY634Jn6DPkuOcC5bkFMQWdOvlYe3+WGx5oabwdtGtm1no9/kt/QZcM0NZL35KP+j0yRe81NhHxaowX1uOHTYOIBHU+n7q0PBdYU4xKYw0kbP12FWrwPlk6P+3fUcTqNgBo4G90cYk9OU4X/66JQC9J/wqXlJWYF2h/aWr+BBK6feW6m76/Ee9kXg43xS237mJv8PrkuoB4pyf4s25N6/RXqgsSeFU6GimzKoIC4hLcd0rkPvceB6on/ZMYR/W14+PRnrzXXKOyHqFy3C8lar6QR1UiwLix9l5dGaPOLQ==")
   return h, true
}

func (digiturk) RequestUrl() (string, bool) {
   return "https://castleblack.digiturk.com.tr/api/widevine/license?version=1.0", true
}

func (digiturk) ResponseBody(b []byte) ([]byte, error) {
   var s struct {
      License []byte
   }
   err := json.Unmarshal(b, &s)
   if err != nil {
      return nil, err
   }
   return s.License, nil
}
