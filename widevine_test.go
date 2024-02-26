package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "net/http"
   "os"
   "testing"
)

var tests = map[string]struct{
   key_id string
   pssh string
   response string
   url string
}{
   "peacock": {
      url:      "peacocktv.com/watch/playback/vod/GMO_00000000224510_02_HDSDR",
      pssh:     "AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgSEAAW4jRz6+d9k9jRpy3GkNdI49yVmwY=",
   },
   "amc": {
      url:      "amcplus.com/movies/blackberry--1065021",
      pssh:     "AAAAVnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADYIARIQJxTtpnq7TjW7URquBXrxahoNd2lkZXZpbmVfdGVzdCIIMTIzNDU2NzgyB2RlZmF1bHQ=",
      response: "CAISmAUKLgoAEiYKENjdMjUvR0YGrT6ycxRoUYcQATIQOlZidDX8oP4f+vmjvE8T8CABKAASHQgBEAAYACAAKAA4AEIASABQAFgAYAFwAHgBgAEAGkYSENRr6+0DE/b11cxxA55CMwYaMMeITu3exSSTH+TmYJTfySIVyXSxHQ+DhZ32LCmsVelSAO3/RnCsr5hrk0sA54JzgCABGmQKEAy2S78vAUQDrjK/GesTkWoSEDliyaUTuja2N6d5MKAT4nUaIENo8Ve7AzsWctoci9w24Lo3viAt9JnyXW2G+AIDuvXeIAIoATIICAEQAxgAIAA6CAgAECoYACAAYgRVSEQxGmIKEP3Bn0gybk/goXwKTwv51vsSEHTQMgJKtYOadMKVCCA+NwQaIDhQY8sX9VMmgzDL5fuVFbQQtqxEnwB6HWKqKzuEA65pIAIoATIICAAQKhgAIAA6CAgAECoYACAAYgJTRBpiChCgnBWNFzRFk7Ax3b+YD5DnEhBslM6nTP1p3MZqVuzqWyRFGiAapEMAB/v7K8YQxFpuXDvq34rgX24H466x8Bv4VDmEAiACKAEyCAgBEAMYACAAOggIABAqGAAgAGICSEQaYgoQ5m+Y78sDQ92nZPPlS0nnUhIQrwpGj99OmpO37p4XKTadJxogLW/NjaiIg88Vo+/CqzibmimZWlXd2nElmVCuDU4+doQgAigBMggIABADGAAgADoICAAQKhgAIABiAkhEGmUKECcU7aZ6u041u1EargV68WoSEG+w+fH6+dLYJ1hlCe3Haj4aILhTXZImifKTcboXhdMkrvL1x+tsOJq2VXxsxA2L18x8IAIoATIICAAQKhgAIAA6CAgAECoYACAAYgVBVURJTyDk9ZWuBjgAGiBdAtcVWGSE4fJyZLEU4Si6o3VZpLnRrQNY6oJ8gM2pGCKAAl0JBd3RxfwOIK/5wwfTTFy9J9HvL9bUkhkDHKaovVGiccaUHtDbuOFC3IcLv0RwGkNO8PJTBSRNG5y6fDvfXMl7nyqDJAFxJZkN6gimrBClmmUSDH+NPNXEbWo5aphK6RpuiX3KKTbDPnRr6VLbp5pyP91ukHHzWBOtED4FmoTYkZXNE73Dwjl/GP+5MXWmtZ6IyRdDmQG6VKsYcJvs4KgPdmPsi/BTbvUpUzFcW4yKJeryG0K9IKDVnwuqBr1/m9ClqXUOLfkbsSu6NdKqIWFbSRwDaBTTfINIUMxabUcaX+eQowcpOh/dZui5y1cJyLomQ4ZFfE6subjP/eIgAvo6CAoGMTguMS4yQAFYAA==",
   },
   "hulu": {
      key_id: "21b82dc2ebb24d5aa9f8631f04726650",
      response: "CAIS/QEKcAoAEmhZMlZyYzE4eU1XSTRNbVJqTWkxbFltSXlMVFJrTldFdFlUbG1PQzAyTXpGbU1EUTNNalkyTlRCZk9EZ3lNVGcwTURrdFpUUmpPUzAwWm1ZNExUa3pZV1V0TVRCaFkySTROREExWVdFNCABKAASHwgBEAAYACAAKAAwADgAQgBIAFAAWABgAHABeAGAAQAaYAoQIbgtwuuyTVqp+GMfBHJmUBIQ/XZ2vXuBNoybDVePqqP7BBogRCL/oBQosn2uJ7MlRtO5AqCXfBgnF1kn7rIHMorpNuYgAigBMggIABAqGAAgADoICAAQKhgAIABiACDEz5WuBjgAGiCEMFB5lSqrct9+hQV2Mu4x5XfWRVlwnIpwS4UmM7r39SKAAjAOMMYopmbBmqg5vv+taYGS8Zg9EyujwjnsYeQ6yMSzcUj8X8kgP5xSP1xK3KioD9Zc6kgb0O00GNQ5jgfyrlf4RVkC/zLoAwsVptW4pLf1zpfs/m1b6l9g2Tcj1pMZoITcTNvmAjElqtyhZh3pXd3wuA3o686fHEkwraSXPYUmdlzGWwkK/7TX1uglQs7nPlj6kIiFxGlea6ARkJTGWpUG+uI4Oj8XmJckLPashjTdYYRTElpAdFuYZjickiM+OR2KDxsC3ODgCdkSz947rRoGRAWckIJ5QKA66o04o5XLg5jDGK3EW41AykM4TkjJoNsq7Ww1LTD+69yCpK3HpDs6CAoGMTguMS4yQAFYAA==",
      url: "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
   },
   "nbc": {
      pssh: "AAAAV3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADcIARIQ/zFt5li1T7C00hLL9vmivhoLYnV5ZHJta2V5b3MiEP8xbeZYtU+wtNISy/b5or4qAkhE",
      response: "CAISqgEKIgoAEhDuKLHulximRa1nEqF4XYRJIAEoADgAQABI2OKVrgYSHAgBEAAYACAAKAAwADgAQgBIAFAAWABgAHAAeAEaXgoQ/zFt5li1T7C00hLL9vmivhIQvWWhoNKHv5S0JT/6Ba3eVRogSleyHHKQQEIEnhgsmng+SXUj0SPoRVaKIsVjmoSG3U8gAigBMggIABAqGAAgADoICAAQKhgAIAAg2OKVrgY4ABog/u1Nm1i3yIDII2YDnnjDnrXnszhQhQEsxpk8udsBdtIigAJ4Kutok8EW/xw5H9GFHK/ryoOSjpigd8+DnayojP93TNINnf+9cOJSuaTfMXnXkMMbuzE7If0f6t2TqH9dFgL+H95MlldYj7B7wH+JaPRXktBRUQqWHk7iSz1p7iR7b+326Gzg7lAYVEOSaG8WZJtGl7Z97YKAuqqCp5RN+SCgZ6V1emPvTqGRI2wUL29YhNitgjtPpdTQLYvLZqXBnW0/9SrkmOifWVLOKg/QBwgkoAF/BGlhlvlgv3u0WtpwIc9NFWyeKbTFG2kJw3nHK89cyDFo63PA1eEUoZsQ0ntyxEGtFbyZEagypTao+DItRAAO1gap85rM9n/AQsvagPkROggKBjE2LjQuNEABWAA=",
      url: "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
   },
   "paramount": {
      pssh: "AAAAWHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADgIARIQPeDzPBuKT86WHtqpUOLnMiIgYnFzSmhfejdvNEFSNmt0dWlfOXk4d0lIcXpFRXFiaHI4AQ==",
      response: "CAIS6gEKGgoAEgiPtUboQP44hiABKAA4AEAASK7vla4GEhwIARAAGAAgACgAMAA4AEIASABQAFgAYAFwAHgBGkYSECuVaGTK0rYTApJ6mFPNer8aMPc9TxjCTjTqDWXn/kYKD65+Dc+Hl4EKxni4JQnycuDfX7C7nxUJItX2KsCceCFXmyABGl4KED3g8zwbik/Olh7aqVDi5zISEAIUstwuQnyfxGqNDPYCn3YaICBfgvJS4vqr4xWi2F83JUNtHFDLy/g0CCdGgv/lpFgeIAIoATIICAAQKhgAIAA6CAgAECoYACAAIK7vla4GOAAaIJoAha40+btxbvaHBn1rinfs+qbO66XznIGGgIH73gPkIoACfKJBakBqe7nt8gvYDbIt0NAkRSnT48TqordmvbgeSLUatEWga63fMSooSMeEFkHm/yJrizUzX45gsjk8r2oPuSIXEfIemAkvz2DKmsPxtxRnwipffUQePJXjEveiqVTMpSkLmuYSXHR5HT7c+rdDNWu1CekT5reM10Rfd5q0PxFdD1gvvU2O92L/g587/fx4YtlsfS6KcF9BaB2CHO700ZcMFKCopWS5Ghdkt354eH7AMdv7YJnDx4DzoK3zTDYYBEPuTHzfL4cjq/82XZEG00OgMWNGALB1uRHUF4iZURj6nQ51Fk2n3byUqqlCYSs8oTdnmLpTJtnPszvmEyeRUjoICgYxNy40LjBAAVgA",
      url: "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
   },
   "roku": { // 2023-11-14 this requires content_id, so PSSH is needed:
      pssh:     "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQvfpNbNs5cC5baB+QYX+afhoKaW50ZXJ0cnVzdCIBKg==",
      response: "CAISpAEKGgoAEggXPQW+cefOWiABKAA4AEAASP/Jka4GEh4IARAAGAAgACgAMNSPCjgAQgBIAFAAWABgAHAAeAEaXgoQvfpNbNs5cC5baB+QYX+afhIQuDBRSyoGAGwlaYpQdRsjkhogqMM+9V1O1jBtFXgXnp94xb8FhRaDS9XK8IvXUhnv0zIgAigBMggIABAqGAAgADoICAAQKhgAIAAg/8mRrgY4ABognM+qtRhBVnCvTtQE9QNlV0jE/97UTEgljGOIow9l9ocigAJZdu2lEhpPuvAkFpoE+V8is7jMtVcUWWQC0zs4el4nnIBa+w9qXpFWTaPb/ny+jNK13dd3kofquNYx4O5r1hUZZhvYPooJ7PJJRc37Q8Z8xlPdo/Bz01lvfrCejwatT0ceMuXnODR0m7X4juLHlo5NPjeapA+O3KDJzBg+ejvSpHsWUrZDbG5XLBpLR8L2cZalApJ3accdGvk/dUNufJhlTvrLn0mO577fSdfewbx2vaRpCQIKlaJDjGasdGj0GpwzgDJRTBCRBYC7x9jCXHwoOq2htq3zmYFAbNxMShRuuwloLQZOWPqgvApYHnwlreP+9ZDyMwciXC1Y40eXFEKNOggKBjE3LjAuMUABWAA=",
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
   },
}

func TestResponse(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range tests {
      protect := func() (p PSSH) {
         if test.pssh != "" {
            b, err := base64.StdEncoding.DecodeString(test.pssh)
            if err != nil {
               t.Fatal(err)
            }
            if err := p.New(b); err != nil {
               t.Fatal(err)
            }
         } else {
            p.Key_ID, err = hex.DecodeString(test.key_id)
            if err != nil {
               t.Fatal(err)
            }
         }
         return
      }()
      module, err := protect.CDM(private_key, client_id)
      if err != nil {
         t.Fatal(err)
      }
      signed, err := base64.StdEncoding.DecodeString(test.response)
      if err != nil {
         t.Fatal(err)
      }
      license, err := module.response(signed)
      if err != nil {
         t.Fatal(err)
      }
      key, ok := module.Key(license)
      if !ok {
         t.Fatal("CDM.Key")
      }
      fmt.Println(test.url)
      fmt.Printf("%x\n\n", key)
   }
}

func TestPssh(t *testing.T) {
   for _, test := range tests {
      if test.pssh != "" {
         var protect PSSH
         data, err := base64.StdEncoding.DecodeString(test.pssh)
         if err != nil {
            t.Fatal(err)
         }
         if err := protect.New(data); err != nil {
            t.Fatal(err)
         }
         fmt.Printf("%q\n", protect.Key_ID)
         fmt.Printf("%q\n\n", protect.content_id)
      }
   }
}
func new_module(raw_pssh, key_id string) (*CDM, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return nil, err
   }
   protect, err := func() (*PSSH, error) {
      var p PSSH
      if raw_pssh != "" {
         b, err := base64.StdEncoding.DecodeString(raw_pssh)
         if err != nil {
            return nil, err
         }
         if err := p.New(b); err != nil {
            return nil, err
         }
      } else {
         var err error
         p.Key_ID, err = hex.DecodeString(key_id)
         if err != nil {
            return nil, err
         }
      }
      return &p, nil
   }()
   if err != nil {
      return nil, err
   }
   return protect.CDM(private_key, client_id)
}

type post struct{}

func (post) RequestBody(b []byte) ([]byte, error) {
   return b, nil
}

func (post) ResponseBody(b []byte) ([]byte, error) {
   return b, nil
}

type roku struct {
   post
}

// therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76
func (roku) RequestUrl() (string, bool) {
   return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc0fDfsqmdLNcKddqPGoQx6HWNhUyrpy0aUXhyCgGZtUZzqgsqAl_RGJF60IOx19vOWVO8HVMcU04Hh4-G3Oy6SUcAaSF49MZCMSSm-rPUKM9HrY2G-mfm3sbX6xIORKllMLb2DHFpJJIhTs4_iTSP5pyktnTOqU0quvQERvpJiioTumJBF73MOrIUN2yW3hZLNA5SZC88QRxguAbadUwD9krAbA2Nh1j5YACLInD2izaLAyASusqIYuNxVi_Pa-wsRW8A-u8hKGSGzmVH3LNjfo-QEiIr5IpQHhndmHN6fup3kMkdeCoHYQ5Qz7heMIsJ3PTh8KjAgYl4USeYEgiG7QyIQ3&traceId=b0de6abe07b1e6bab52cd87d490b3741&ExpressPlayToken=none", true
}

func (roku) RequestHeader([]byte) (http.Header, error) {
   return http.Header{}, nil
}
