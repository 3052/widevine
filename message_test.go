package widevine

import (
   "fmt"
   "log/slog"
   "net/http"
   "testing"
)

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
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1ODK0omdCaI6dfpfepQx7VWdxUyu8v36UYhiWjHZpRZzugsPUl_UvbRf4Ia0t-vLHFP5bbYJFi5H0i_W3Pm_aeI1aXGI5PZCMSOhqQPEKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIwJGFTx9586BxopmUqm-BZoWYJdu4&traceId=8b66614f0c2528354179a864f3c26852&ExpressPlayToken=none", true
}

func (roku) RequestHeader() (http.Header, error) {
   return http.Header{}, nil
}
