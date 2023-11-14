package widevine

import (
   "fmt"
   "net/http"
   "os"
   "testing"
)

func (hulu) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (hulu) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

type hulu struct{}

func (hulu) Request_Header() http.Header {
   h := make(http.Header)
   // is this needed?
   h["User-Agent"] = []string{"Widevine CDM v1.0"}
   return h
}

var post_pssh = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\b\x02\x12\"\n \n\x17\b\x80\n\x10\xd0\x05\"\x04H264*\x04HIGH2\x035.2\x12\x05FIRST\x1a\x0e\n\f\n\x05\n\x03AAC\x12\x03ONE\"\x1e\n\x17\n\bWIDEVINE\x12\aMODULAR\x1a\x02L3\x12\x03ONE*\f\n\x04DASH\x10\x01 \x01X\x032\x1b\n\x14\n\x04FMP4\x12\f\n\x04CENC\x12\x04CENC\x12\x03ONE@\x01P\xa6\x01")

func (hulu) Request_URL() string {
   return "https://hulu.playback.edge.bamgrid.com/widevine-hulu/v1/hulu/vod/obtain-license-legacy/196861183?deejay_device_id=166&nonce=252683275&signature=1699961759_2a1b1677b2f02befae6f92e883ced80ce092b21c"
}

func Test_Key(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   client_ID, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   mod, err := New_Module(private_key, client_ID, post_pssh)
   if err != nil {
      t.Fatal(err)
   }
   key, err := mod.Key(hulu{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}
