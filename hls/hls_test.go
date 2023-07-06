package hls

import (
   "bytes"
   "fmt"
   "io"
   "net/http"
   "os"
   "testing"
)

// gem.cbc.ca/downton-abbey/s01e04
const hls_encrypt = "https://cbcrcott-gem.akamaized.net/95bc1901-988d-400a-a7a3-624284880413/CBC_DOWNTON_ABBEY_S01E04.ism/QualityLevels(400047)/Manifest(video,format=m3u8-aapl)"

func Test_Block(t *testing.T) {
   res, err := http.Get(hls_encrypt)
   if err != nil {
      t.Fatal(err)
   }
   if res.StatusCode != http.StatusOK {
      t.Fatal(res.Status)
   }
   seg, err := New_Scanner(res.Body).Segment()
   if err != nil {
      t.Fatal(err)
   }
   if err := res.Body.Close(); err != nil {
      t.Fatal(err)
   }
   key, err := get_key(seg.Key)
   if err != nil {
      t.Fatal(err)
   }
   file, err := os.Create("ignore.ts")
   if err != nil {
      t.Fatal(err)
   }
   defer file.Close()
   block, err := New_Block(key)
   if err != nil {
      t.Fatal(err)
   }
   for i := 0; i <= 9; i++ {
      req, err := http.NewRequest("GET", seg.URI[i], nil)
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(req.URL)
      req.URL = res.Request.URL.ResolveReference(req.URL)
      res, err := new(http.Transport).RoundTrip(req)
      if err != nil {
         t.Fatal(err)
      }
      text, err := io.ReadAll(res.Body)
      if err != nil {
         t.Fatal(err)
      }
      text = block.Decrypt_Key(text)
      if _, err := file.Write(text); err != nil {
         t.Fatal(err)
      }
      if err := res.Body.Close(); err != nil {
         t.Fatal(err)
      }
   }
}

var segment_tests = []string{
   "m3u8/cbc-audio.m3u8.txt",
   "m3u8/cbc-video.m3u8.txt",
   "m3u8/nbc-segment.m3u8.txt",
   "m3u8/roku-segment.m3u8.txt",
}

func Test_Segment(t *testing.T) {
   for _, test := range segment_tests {
      text, err := reverse(test)
      if err != nil {
         t.Fatal(err)
      }
      seg, err := New_Scanner(bytes.NewReader(text)).Segment()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Printf("%+v\n\n", seg)
   }
}

var raw_ivs = []string{
   "00000000000000000000000000000001",
   "0X00000000000000000000000000000001",
   "0x00000000000000000000000000000001",
}

func Test_Hex(t *testing.T) {
   for _, raw_iv := range raw_ivs {
      iv, err := Segment{Raw_IV: raw_iv}.IV()
      if err != nil {
         t.Fatal(err)
      }
      fmt.Println(iv)
   }
}

func get_key(s string) ([]byte, error) {
   res, err := http.Get(s)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   return io.ReadAll(res.Body)
}
