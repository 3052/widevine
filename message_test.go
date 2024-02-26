package widevine

import (
   "fmt"
   "log/slog"
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

func TestPeacock(t *testing.T) {
   test := tests["peacock"]
   module, err := new_module(test.pssh, test.key_id)
   if err != nil {
      t.Fatal(err)
   }
   slog.SetLogLoggerLevel(slog.LevelDebug)
   license, err := module.License(peacock{})
   if err != nil {
      t.Fatal(err)
   }
   key, ok := module.Key(license)
   fmt.Printf("%x %v\n", key, ok)
}
