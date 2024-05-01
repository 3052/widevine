package widevine

import (
   "encoding/json"
   "fmt"
   "testing"
)

func TestAmc(t *testing.T) {
   key, err := request("amc", nil)
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

func TestRoku(t *testing.T) {
   key, err := request("roku", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestMubi(t *testing.T) {
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
   key, err := request("mubi", unwrap)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestHulu(t *testing.T) {
   key, err := request("hulu", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestNbc(t *testing.T) {
   key, err := request("nbc", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func TestParamount(t *testing.T) {
   key, err := request("paramount", nil)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

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
