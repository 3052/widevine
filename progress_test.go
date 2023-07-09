package curl

import (
   "io"
   "net/http"
   "testing"
   "time"
)

const (
   go_big = "https://dl.google.com/go/go1.20.5.windows-amd64.zip"
   go_small = "https://go.dev/dl/"
)

func Test_Big(t *testing.T) {
   pro := New_Progress(1)
   res, err := http.Get(go_big)
   if err != nil {
      t.Fatal(err)
   }
   if _, err := io.ReadAll(pro.Reader(res)); err != nil {
      t.Fatal(err)
   }
   if err := res.Body.Close(); err != nil {
      t.Fatal(err)
   }
}

func Test_Small(t *testing.T) {
   var smalls [9]struct{}
   pro := New_Progress(len(smalls))
   tr := http.Transport{DisableCompression: true}
   req, err := http.NewRequest("GET", go_small, nil)
   if err != nil {
      t.Fatal(err)
   }
   for range smalls {
      res, err := tr.RoundTrip(req)
      if err != nil {
         t.Fatal(err)
      }
      if _, err := io.ReadAll(pro.Reader(res)); err != nil {
         t.Fatal(err)
      }
      if err := res.Body.Close(); err != nil {
         t.Fatal(err)
      }
      time.Sleep(99 * time.Millisecond)
   }
}
