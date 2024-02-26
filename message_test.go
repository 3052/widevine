package widevine

import (
   "fmt"
   "log/slog"
   "net/http"
   "testing"
)

func TestPeacock(t *testing.T) {
   test := tests["peacock"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   if _, err := module.License(peacock{}); err != nil {
      t.Fatal(err)
   }
}

type peacock struct {
   post
}

func (peacock) RequestHeader([]byte) (http.Header, error) {
   return http.Header{}, nil
}

// peacocktv.com/watch/playback/vod/GMO_00000000224510_02_HDSDR
func (peacock) RequestUrl() (string, bool) {
   return "https://ovp.peacocktv.com/drm/widevine/acquirelicense?bt=98-K1UA1n6NSWJt4lSwWvj-AC_nbp5I9be6RK1WVu1zw0fqsLMWVe4nqmx58NDU1DJaDLR4gZJi9VBx-QtkAoyOeANzRqqkbQMK2ZF_1uVkBq0XfJ0Vqth1QtSiOfiEPVtHn1Tk-xydhrXsTyTxfw5fHJkvEJ1wa1q9W3oOnubIzijwee2YQPMt596ESk8tDpxF6xoKSOsobSYMkW77LzKJ_fGLbUPPi0Mtl2b-Z-_ybnrJ-TD72wtrBQ4TbCrPzBH8OtLftoFTejaxPdZ6unxkTTCbCYITkIxVuDBDvqcJQocB-N0585z7ZmOHFxtS0u2LGC4WdzGrnhZ2-_i6Bw_bk3ZDIYxZQFArM0J8-LyMQMMCmDcErZPwIHeG8gt843zypy8Zlp9o", true
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
