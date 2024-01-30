package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "net/http"
   "os"
   "testing"
)

func Test_Roku(t *testing.T) {
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
   pssh, err := base64.StdEncoding.DecodeString(tests[1].pssh)
   if err != nil {
      t.Fatal(err)
   }
   var module DecryptionModule
   if err := module.PSSH(private_key, client_ID, pssh); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(roku{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func Test_Hulu(t *testing.T) {
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
   key_id, err := hex.DecodeString(hulu_key_id)
   if err != nil {
      t.Fatal(err)
   }
   var module DecryptionModule
   if err := module.Key_ID(private_key, client_ID, key_id); err != nil {
      t.Fatal(err)
   }
   key, err := module.Key(hulu{})
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", key)
}

func (hulu) Request_Header() (http.Header, bool) {
   return nil, false
}

func (roku) Request_Header() (http.Header, bool) {
   return nil, false
}

type hulu struct{}

func (hulu) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (hulu) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

type roku struct{}

func (roku) Request_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (roku) Response_Body(b []byte) ([]byte, error) {
   return b, nil
}

func (hulu) Request_URL() (string, bool) {
   return "https://hulu.playback.edge.bamgrid.com/widevine-hulu/v1/hulu/vod/obtain-license-legacy/196861183?deejay_device_id=166&nonce=252683275&signature=1701864514_f7e7ce0e7cefdaa486b3d768538e62f7a6df2fbd", true
}

// hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d
const hulu_key_id = "21b82dc2ebb24d5aa9f8631f04726650"

func (roku) Request_URL() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1OC60pyoOcJKdcqPijQx6HVItUye512qUS1nOhHs4FZ2ikuPAl_UffRq4PYkh-uuDOb5CHZ5Ni5nh_rDPOnvbPJAGQFo0ZZCMSAyu-PkKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMI-cLaTR8efMmryKVF_CEZMt9E8PFk&traceId=4f5f187f629e4d47432d0f71fbde166d&ExpressPlayToken=none", true
}
