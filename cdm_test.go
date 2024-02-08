package widevine

import (
   "encoding/base64"
   "fmt"
   "log/slog"
   "net/http"
   "os"
   "testing"
)

func TestRoku(t *testing.T) {
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
   test := tests["roku"]
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
   module, err := protect.Cdm(private_key, client_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(roku(roku_license))
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

const roku_license = "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0WCv8ozdHNJKcNqveoQx6GU9hUke0i0KVFhSPwEJoDM2_14aIl_RGOFvpcbhl77uSSPsXTMZVu4nx5qWLIyqnOd1TAQYxNZCMSTjTJPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMItPatTh_rCS9YohaDtC13-pxNypWg&traceId=b7e2b4fcb6e4a0b1876b571e9c70aa70&ExpressPlayToken=none"

type roku string

func (r roku) RequestUrl() (string, bool) {
   return string(r), true
}

func (roku) RequestHeader() (http.Header, bool) {
   return nil, false
}

func (roku) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) ResponseBody(b []byte) ([]byte, error) {
   return b, nil
}
