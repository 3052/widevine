package main

import (
   "154.pages.dev/widevine"
   "encoding/base64"
   "encoding/json"
   "flag"
   "fmt"
   "log/slog"
   "net/http"
   "os"
   "path/filepath"
)

func (flags) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (flags) RequestUrl() (string, bool) {
   return "https://castleblack.digiturk.com.tr/api/widevine/license?version=1.0", true
}

func (flags) ResponseBody(b []byte) ([]byte, error) {
   var s struct {
      License []byte
   }
   err := json.Unmarshal(b, &s)
   if err != nil {
      return nil, err
   }
   return s.License, nil
}

func (f flags) RequestHeader() (http.Header, bool) {
   h := make(http.Header)
   h.Set("authorization", "Bearer " + f.authorization)
   h.Set("X-CB-Ticket", f.ticket)
   return h, true
}

type flags struct {
   client_id string
   pssh string
   private_key string
   authorization string
   ticket string
   protect widevine.Pssh
}

func main() {
   home, err := os.UserHomeDir()
   if err != nil {
      panic(err)
   }
   home = filepath.ToSlash(home) + "/widevine/"
   var f flags
   flag.StringVar(&f.authorization, "a", "", "authorization")
   flag.StringVar(&f.client_id, "c", home+"client_id.bin", "client ID")
   flag.StringVar(&f.private_key, "k", home+"private_key.pem", "private key")
   flag.StringVar(&f.pssh, "p", "", "PSSH")
   flag.StringVar(&f.ticket, "x", "", "X-CB-Ticket")
   flag.Parse()
   if f.pssh != "" {
      module, err := f.module()
      if err != nil {
         panic(err)
      }
      slog.SetLogLoggerLevel(slog.LevelDebug)
      license, err := module.License(f)
      if err != nil {
         panic(err)
      }
      key, ok := module.Key(license)
      fmt.Printf("%x:%x %v\n", f.protect.Key_id, key, ok)
   } else {
      flag.Usage()
   }
}

func (f *flags) module() (*widevine.Cdm, error) {
   private_key, err := os.ReadFile(f.private_key)
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(f.client_id)
   if err != nil {
      return nil, err
   }
   data, err := base64.StdEncoding.DecodeString(f.pssh)
   if err != nil {
      return nil, err
   }
   if err := f.protect.New(data); err != nil {
      return nil, err
   }
   return f.protect.Cdm(private_key, client_id)
}
