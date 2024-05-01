package widevine

import (
   "encoding/json"
   "fmt"
   "testing"
)

func TestStan(t *testing.T) {
   unwrap := func(b []byte) ([]byte, error) {
      var s struct {
         License []byte
      }
      err := json.Unmarshal(b, &s)
      if err != nil {
         return nil, err
      }
      return s.License, nil
   }
   key, err := request("stan", unwrap)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestCtv(t *testing.T) {
   key, err := request("ctv", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}
