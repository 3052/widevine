package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "os"
   "testing"
)

var tests = map[string]struct{
   key_id string
   pssh string
   response string
   url string
}{
   "amcplus": {
      pssh:     "AAAAVnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADYIARIQd41tdrKESTqmJnLHZiJ/nxoNd2lkZXZpbmVfdGVzdCIIMTIzNDU2NzgyB2RlZmF1bHQ=",
      response: "",
      url:      "amcplus.com/movies/perfect-blue--1058032",
   },
   "hulu": {
      key_id: "21b82dc2ebb24d5aa9f8631f04726650",
      response: "",
      url: "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
   },
   "nbc": {
      pssh: "AAAAV3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADcIARIQ/zFt5li1T7C00hLL9vmivhoLYnV5ZHJta2V5b3MiEP8xbeZYtU+wtNISy/b5or4qAkhE",
      response: "",
      url: "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
   },
   "paramountplus": {
      pssh: "AAAAWHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADgIARIQPeDzPBuKT86WHtqpUOLnMiIgYnFzSmhfejdvNEFSNmt0dWlfOXk4d0lIcXpFRXFiaHI4AQ==",
      response: "",
      url: "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
   },
   "roku": { // 2023-11-14 this requires content_id, so PSSH is needed:
      pssh:     "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQvfpNbNs5cC5baB+QYX+afhoKaW50ZXJ0cnVzdCIBKg==",
      response: "CAISpAEKGgoAEggXPQW+cefOWiABKAA4AEAASP/Jka4GEh4IARAAGAAgACgAMNSPCjgAQgBIAFAAWABgAHAAeAEaXgoQvfpNbNs5cC5baB+QYX+afhIQuDBRSyoGAGwlaYpQdRsjkhogqMM+9V1O1jBtFXgXnp94xb8FhRaDS9XK8IvXUhnv0zIgAigBMggIABAqGAAgADoICAAQKhgAIAAg/8mRrgY4ABognM+qtRhBVnCvTtQE9QNlV0jE/97UTEgljGOIow9l9ocigAJZdu2lEhpPuvAkFpoE+V8is7jMtVcUWWQC0zs4el4nnIBa+w9qXpFWTaPb/ny+jNK13dd3kofquNYx4O5r1hUZZhvYPooJ7PJJRc37Q8Z8xlPdo/Bz01lvfrCejwatT0ceMuXnODR0m7X4juLHlo5NPjeapA+O3KDJzBg+ejvSpHsWUrZDbG5XLBpLR8L2cZalApJ3accdGvk/dUNufJhlTvrLn0mO577fSdfewbx2vaRpCQIKlaJDjGasdGj0GpwzgDJRTBCRBYC7x9jCXHwoOq2htq3zmYFAbNxMShRuuwloLQZOWPqgvApYHnwlreP+9ZDyMwciXC1Y40eXFEKNOggKBjE3LjAuMUABWAA=",
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
   },
}

func TestPssh(t *testing.T) {
   for _, test := range tests {
      if test.pssh != "" {
         var protect Pssh
         data, err := base64.StdEncoding.DecodeString(test.pssh)
         if err != nil {
            t.Fatal(err)
         }
         if err := protect.New(data); err != nil {
            t.Fatal(err)
         }
         fmt.Printf("%q\n", protect.Key_id)
         fmt.Printf("%q\n\n", protect.content_id)
      }
   }
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
      protect := func() (p Pssh) {
         if test.key_id != "" {
            b, err := hex.DecodeString(test.key_id)
            if err != nil {
               t.Fatal(err)
            }
            p.Key_id = b
            return
         }
         b, err := base64.StdEncoding.DecodeString(test.pssh)
         if err != nil {
            t.Fatal(err)
         }
         if err := p.New(b); err != nil {
            t.Fatal(err)
         }
         return
      }()
      module, err := protect.Cdm(private_key, client_id)
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
         t.Fatal("Cdm.Key")
      }
      fmt.Println(test.url)
      fmt.Printf("%x\n\n", key)
   }
}
