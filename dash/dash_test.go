package dash

import (
   "bytes"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func Test_Video(t *testing.T) {
   for _, name := range tests {
      text, err := os.ReadFile(name)
      if err != nil {
         t.Fatal(err)
      }
      reps, err := Representers(bytes.NewReader(text))
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(name)
      for i, rep := range reps {
         if i >= 1 {
            fmt.Println()
         }
         fmt.Println(rep)
      }
      fmt.Println()
   }
}

func Test_Info(t *testing.T) {
   for _, name := range tests {
      text, err := os.ReadFile(name)
      if err != nil {
         t.Fatal(err)
      }
      reps, err := Representers(bytes.NewReader(text))
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(name)
      for i, rep := range reps {
         if i >= 1 {
            fmt.Println()
         }
         fmt.Println(rep)
      }
      fmt.Println()
   }
}

func Test_Media(t *testing.T) {
   text, err := os.ReadFile("mpd/roku.mpd")
   if err != nil {
      t.Fatal(err)
   }
   reps, err := Representers(bytes.NewReader(text))
   if err != nil {
      t.Fatal(err)
   }
   base, err := http.NewRequest("", "http://example.com", nil)
   if err != nil {
      t.Fatal(err)
   }
   for _, ref := range reps[0].Segment_Template.Get_Media() {
      req, err := http.NewRequest("", ref, nil)
      if err != nil {
         t.Fatal(err)
      }
      req.URL = base.URL.ResolveReference(req.URL)
      fmt.Println(req.URL)
   }
}

var tests = []string{
   "mpd/amc.mpd",
   "mpd/paramount.mpd",
   "mpd/roku.mpd",
}

func Test_Ext(t *testing.T) {
   for _, name := range tests {
      text, err := os.ReadFile(name)
      if err != nil {
         t.Fatal(err)
      }
      reps, err := Representers(bytes.NewReader(text))
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(name)
      for _, rep := range reps {
         fmt.Printf("%q\n", rep.Ext())
      }
      fmt.Println()
   }
}

func Test_Audio(t *testing.T) {
   for _, name := range tests {
      text, err := os.ReadFile(name)
      if err != nil {
         t.Fatal(err)
      }
      reps, err := Representers(bytes.NewReader(text))
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(name)
      for i, rep := range reps {
         if i >= 1 {
            fmt.Println()
         }
         fmt.Println(rep)
      }
      fmt.Println()
   }
}
