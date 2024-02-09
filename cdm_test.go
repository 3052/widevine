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

func new_module(pssh, key_id string) (*Cdm, error) {
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
   protect, err := func() (*Pssh, error) {
      var p Pssh
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
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

func (roku) RequestUrl() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1NCqB8ztXGI6dbqPKtQx6EBYpUkOoui6VE0XDzTMhXMD2vtaAl_UvcRvtaYx0gveHBaZ3WN5Y05Xgjq2SYzqSUcVLAEtgeZCMSBG7yPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMI_p2mTh91RI_2y1OCSDQBBuO3yLbx&traceId=8e53d9b8136c95d2b02871aa4916a2cc&ExpressPlayToken=none", true
}

func (hulu) RequestUrl() (string, bool) {
   return "https://hulu.playback.edge.bamgrid.com/widevine-hulu/v1/hulu/vod/obtain-license-legacy/196861183?deejay_device_id=166&nonce=260592616&signature=1707469382_3724304c40d6e0c31e7eb51a070b3928a989831f", true
}

func TestHulu(t *testing.T) {
   test := tests["hulu"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(hulu{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

func (hulu) RequestHeader() (http.Header, bool) {
   return nil, false
}

func (roku) RequestHeader() (http.Header, bool) {
   return nil, false
}

type roku struct {
   post
}

type hulu struct {
   post
}

func TestNbc(t *testing.T) {
   test := tests["nbc"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(nbc{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

func (nbc) RequestHeader() (http.Header, bool) {
   h := make(http.Header)
   h.Set("content-type", "application/octet-stream")
   return h, true
}

func (nbc) RequestUrl() (string, bool) {
   return "https://drmproxy.digitalsvc.apps.nbcuni.com/drm-proxy/license/widevine?time=1707438406589&hash=10e071bbe19abd99a9fbc28e4dc999f53487aed82b1aff629fc1d124294327ee&device=web", true
}

type nbc struct {
   post
}

func TestParamount(t *testing.T) {
   test := tests["paramount"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(paramount{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

type paramount struct {
   post
}

func (paramount) RequestHeader() (http.Header, bool) {
   h := make(http.Header)
   h.Set("authorization", "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6IjNkNjg4NGJmLWViMDktNDA1Zi1hOWZjLWU0NGE1NmY3NjZiNiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9ueW1vdXNfVVMiLCJlbnQiOlt7ImJpZCI6IkFsbEFjY2Vzc01haW4iLCJlcGlkIjo3fV0sImlhdCI6MTcwNzQzOTk3NCwiZXhwIjoxNzA3NDQ3MTc0LCJpc3MiOiJjYnMiLCJhaWQiOiJjYnNpIiwiaXNlIjp0cnVlLCJqdGkiOiJjYjAzZjhhMS05NzA5LTQxY2ItYjYzZi0yM2Y5YjRjMTA2OWQifQ.FQ1YVic69LrlxuwRDHRZEehzuW_xz2WjnGWACYSOQW8")
   return h, true
}

func (paramount) RequestUrl() (string, bool) {
   return "https://cbsi.live.ott.irdeto.com/widevine/getlicense?CrmId=cbsi&AccountId=cbsi&SubContentType=Default&contentId=bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr", true
}

func TestAmc(t *testing.T) {
   test := tests["amc"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(amc{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(test.url)
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}

type amc struct {
   post
}

func (amc) RequestUrl() (string, bool) {
   return "https://manifest.prod.boltdns.net/license/v1/cenc/widevine/6245817279001/38f59301-5b9d-4233-b212-89e64e9d4e6a/e66f98ef-cb03-43dd-a764-f3e54b49e752?fastly_token=NjVjNWVmODhfZmZhNTJjMWM0NWFlY2M4NjIwZmNhNGJkYTA3YTAwNzQ4YzJhNDdkNjhkOTdmZGI1N2YxNTY1ZTcwOTM1YjZkMA%3D%3D", true
}

func (amc) RequestHeader() (http.Header, bool) {
   h := make(http.Header)
   h.Set("bcov-auth", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJiNzIzMDc3OC1iNTViLTRiNzAtYTU2MC00NGUyNTM5YmQ3ZGMiLCJhY2NpZCI6IjYyNDU4MTcyNzkwMDEiLCJwcmlkIjoiODJkMWI0MmEtMWQ0Mi00ZGZiLTg2MmUtNTNmZDhkNWU2NmE4IiwiY29uaWQiOiI2MzQwNjE1ODgzMTEyIiwiY2xpbWl0Ijo0LCJleHAiOjE3MDc1MjcxMjIsImNiZWgiOiJCTE9DS19ORVdfVVNFUiIsImlhdCI6MTcwNzQ0MDcyMiwianRpIjoiNmRkYTA2MTgtNmYwZi00ZGVlLTkwZmEtNjlhMTdkNzQzNTRhIiwic2lkIjoiR28taHR0cC1jbGllbnQvMi4wIC0gNzUxMzQ3ODcwMSJ9.hFcANEj7g60k-UKSOjDuQSaB3aaPn2alAS9sGNMTwh1pkQaXMwASuN74ymIx-_d1go-Bn0HFxfVnCvsgJBFzqlQ9m8bsM1nwIBqGD5kmo4ADKXr-36cy0bDojErnCPyAWPPRr4d2A2NVvFMrizVqTHGzT8i_zaqS5lN_BYdA3gnVuaQH7-eyqG3IvP4Bh-uCbkwv4fhxJLl71dInbMXYSEwek94cnWApW2nuvpdFWiY7SrGRk2Ap2W4L1Jr85ll6R6JmRkZEW_qBOdcy61Ysa7SY88aOiTbCSK1Y9unarBFka8fSS7asX02ebsJawMPFqCbgAS2v668XQFFd0iA8mg")
   return h, true
}
