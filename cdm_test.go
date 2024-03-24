package widevine

import (
   "fmt"
   "log/slog"
   "net/http"
   "testing"
)

type post struct{}

func (post) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (post) ResponseBody(b []byte) ([]byte, error) {
   return b, nil
}

type roku struct {
   post
}

// therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76
func (roku) RequestUrl() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0dB_x-n9SaIqcHqKX6Qx6GVYxUyesnjKUSgnH7TM5UZjzytfYl_UuLRP4HYxwvtODCbsGCasdh5Cx_rGXNmaKbc1ySEd4eZCMSSz3ZI0KM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIsc-9UB9A9850soecAek7U5c3ZPGV&traceId=827699c7825dea9c71fd0046263831ec&ExpressPlayToken=none", true
}

func (roku) RequestHeader() (http.Header, error) {
   return http.Header{}, nil
}

func TestRoku(t *testing.T) {
   test := tests["roku"]
   module, err := new_module(test.pssh)
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
