package hls

import (
   "2a.pages.dev/rosso/slices"
   "bytes"
   "fmt"
   "os"
   "sort"
   "testing"
)

func Test_Stream(t *testing.T) {
   for _, name := range master_tests {
      text, err := reverse(name)
      if err != nil {
         t.Fatal(err)
      }
      master, err := New_Scanner(bytes.NewReader(text)).Master()
      if err != nil {
         t.Fatal(err)
      }
      slices.Sort(master.Stream, func(a, b Stream) bool {
         return b.Bandwidth < a.Bandwidth
      })
      target := slices.Index(master.Stream, func(a Stream) bool {
         return a.Bandwidth <= 9_000_000
      })
      fmt.Println(name)
      for i, value := range master.Stream {
         if i >= 1 {
            fmt.Println()
         }
         if i == target {
            fmt.Print("!")
         }
         fmt.Println(value)
      }
      fmt.Println()
   }
}

func reverse(name string) ([]byte, error) {
   text, err := os.ReadFile(name)
   if err != nil {
      return nil, err
   }
   sort.SliceStable(text, func(int, int) bool {
      return true
   })
   return text, nil
}

var master_tests = []string{
   "m3u8/cbc-master.m3u8.txt",
   "m3u8/nbc-master.m3u8.txt",
   "m3u8/roku-master.m3u8.txt",
}

func Test_Info(t *testing.T) {
   for _, name := range master_tests {
      text, err := reverse(name)
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(name)
      master, err := New_Scanner(bytes.NewReader(text)).Master()
      if err != nil {
         t.Fatal(err)
      }
      for i, value := range master.Stream {
         if i >= 1 {
            fmt.Println()
         }
         fmt.Println(value)
      }
      fmt.Println()
      for i, value := range master.Media {
         if i >= 1 {
            fmt.Println()
         }
         fmt.Println(value)
      }
      fmt.Println()
   }
}

func Test_Media(t *testing.T) {
   for _, name := range master_tests {
      text, err := reverse(name)
      if err != nil {
         t.Fatal(err)
      }
      master, err := New_Scanner(bytes.NewReader(text)).Master()
      if err != nil {
         t.Fatal(err)
      }
      target := slices.Index(master.Media, func(m Media) bool {
         return m.Name == "English"
      })
      fmt.Println(name)
      for i, media := range master.Media {
         if i == target {
            fmt.Print("!")
         }
         fmt.Println(media)
      }
      fmt.Println()
   }
}

