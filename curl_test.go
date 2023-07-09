package curl

import (
   "fmt"
   "net/http"
   "testing"
)

func Test_Location(t *testing.T) {
   {
      no_location()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
   {
      location()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
}

func Test_Trace(t *testing.T) {
   {
      trace()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
   {
      no_trace()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
}

func Test_Verbose(t *testing.T) {
   {
      verbose()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
   {
      no_verbose()
      status, err := get()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(status)
   }
}

func get() (string, error) {
   res, err := http.Get("http://godocs.io")
   if err != nil {
      return "", err
   }
   if err := res.Body.Close(); err != nil {
      return "", err
   }
   return res.Status, nil
}
