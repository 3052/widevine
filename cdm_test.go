package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "log/slog"
   "net/http"
   "os"
   "testing"
)

func new_module(raw_pssh, key_id string) (*CDM, error) {
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
   protect, err := func() (*PSSH, error) {
      var p PSSH
      if raw_pssh != "" {
         b, err := base64.StdEncoding.DecodeString(raw_pssh)
         if err != nil {
            return nil, err
         }
         if err := p.New(b); err != nil {
            return nil, err
         }
      } else {
         var err error
         p.Key_ID, err = hex.DecodeString(key_id)
         if err != nil {
            return nil, err
         }
      }
      return &p, nil
   }()
   if err != nil {
      return nil, err
   }
   return protect.CDM(private_key, client_id)
}

type post struct{}

func (post) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (post) ResponseBody(b []byte) ([]byte, error) {
   return b, nil
}

func TestRoku(t *testing.T) {
   test := tests["roku"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(roku{})
   if err != nil {
      t.Fatal(err)
   }
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

type roku struct {
   post
}

// therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76
func (roku) RequestUrl() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0fDfsqmdLNcKddqPGoQx6HWNhUyrpy0aUXhyCgGZtUZzqgsqAl_RGJF60IOx19vOWVO8HVMcU04Hh4-G3Oy6SUcAaSF49MZCMSSm-rPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIsJ3PTh8KjAgYl4USeYEgiG7QyIQ3&traceId=b0de6abe07b1e6bab52cd87d490b3741&ExpressPlayToken=none", true
}

func (roku) RequestHeader([]byte) (http.Header, error) {
   return http.Header{}, nil
}
