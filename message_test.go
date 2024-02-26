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
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0bDawpz4KacqdfqvGjQx6HBY5Uke8h3aUT1yCkH8sNMT6n4fcl_UWOSqwGO0Z8urfDP5LXapVi53x6rTGbzfbPdlHEGN4YZCMSAT-uPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMI-87KTh9Dantr4awBBl2zpa1qFOx7&traceId=679d8a9d6e456491426a1dbbfb65e8ee&ExpressPlayToken=none", true
}

func (roku) RequestHeader() (http.Header, error) {
   return http.Header{}, nil
}
