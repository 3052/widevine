package widevine

import (
   "encoding/base64"
   "fmt"
   "os"
   "testing"
)

var tests = []struct {
   url      string
   pssh     string
   response string
}{
   {
      url:      "amcplus.com/movies/perfect-blue--1058032",
      pssh:     "AAAAVnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADYIARIQd41tdrKESTqmJnLHZiJ/nxoNd2lkZXZpbmVfdGVzdCIIMTIzNDU2NzgyB2RlZmF1bHQ=",
      response: "CAISlQUKLgoAEiYKEJ/rB4ZCLEyVn6XTC+W3Nv8QATIQOlZidDX8oP4f+vmjvE8T8CABKAASGggBEAAYACAAKAA4AEIASABQAFgAYAFwAHgAGkYSEMCmKfvJNXnbGzNp0C3r4NAaMIs+rLPSBpQSq0TCJQsoGUo09csN5gUOhzhJRUnt9E0qOwVbHN4yEp2mw5d+hkgfpSABGmIKEHeNbXayhEk6piZyx2Yif58SENf+WiQGUzNjNocT2HbvbYkaICBC4HiS//GVEMGo724evKinuvU89HJ6tFwszHhiHSGEIAIoATIICAAQKhgAIAA6CAgAECoYACAAYgJTRBpkChCpRhFtg8xPbLyJN9H0L4/oEhCq9Y6IrxDj3xTtwILguoKYGiA3FGSNeYR4kSPKoVQ2csRFbld4Sfaetm49+set8xtkRiACKAEyCAgBEAMYACAAOggIABAqGAAgAGIEVUhEMRplChCVfhTPb/hF6ZInvPHzNEw+EhA3tbzVVism8VjFKZU+juMgGiA90JHmKATDEzazT5xrrnQNPh4kgAS6j1ajPu9qNry6piACKAEyCAgAECoYACAAOggIABAqGAAgAGIFQVVESU8aYgoQC/ymvo2ETa+XnK+6qXy5nRIQpStUxZGB4ihGz4mLjYuDzxogL50JqgtaPt1O8ANCofYRmRYkKpNQ6tyjdSWdEUqkCdMgAigBMggIARADGAAgADoICAAQKhgAIABiAkhEGmIKECMh14jAKkG1pWXOBwRyAJgSEJN9Biw3JbFe7GJI6r8VQRwaIGUq3SuFEK29jRjzvHI9GJwwF1QvG7HbFgZLBlqNFtCOIAIoATIICAAQAxgAIAA6CAgAECoYACAAYgJIRCDJ8/SnBjgAGiBIOSjkKTnfLSzl/h1ZMZCEJir+3xljpOGMERedNMKG6iKAAgLgSQZ2i8Tu1RfovWDdDuOf67wdayidfeSG4+fBOmdNIg6CsqBE7VCSzP68FdiDxm6TPAdo7x5Uf4wtIs++MDB/cRKwtWbvtMyyyUxOAz/795I6DEe16t4PI3nbEvdos5XSgHXdtpiJz7PC1EULbz/IClMqNtfnsPqozNn8eENxR+nxdXmQzEuV7LnIlNi0E5GctsPRT46Bav1gLD5yNusqiBkQ+3j2kriG9I1N9yuUwm9c5HZAckdv7/Hr8jJeFALC7kC7jByUeC0yHrd/AuuJ/WcDr7QE5CYo1BnVNEvFOmAbjaguYul5JVnKCcJH8Q/rkWRv4rZY4vasWDufrTs6CAoGMTguMC4xQAFYAA==",
   },
   {
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
      pssh:     "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQvfpNbNs5cC5baB+QYX+afhoKaW50ZXJ0cnVzdCIBKg==",
      response: "CAISpAEKGgoAEghBPi3uL18dhiABKAA4AEAASOrh758GEh4IARAAGAAgACgAMMnFCjgAQgBIAFAAWABgAHAAeAEaXgoQvfpNbNs5cC5baB+QYX+afhIQUkaPkIyfx8bplsyEg21YKhogQYRNMicID9i4twGGFm/fdKEmJGUVQuNnBXXfUtmYXH4gAigBMggIABAqGAAgADoICAAQKhgAIAAg6uHvnwY4ABoga0R69yOAW/lmax2ng2W92p0JzaIz+GNvKhgucUFs0qsigAKU3+gmgfhY4c6YXXDpAi5lt192PUBfXUCJ6WX+zu3haUI1sY9VxA389iUQ470xm6SW5mF2vcFg7NUeCFEeq+Y15GgZnN9JuLWOq7GQIqsQioLpKvQMIwEamd/KP16KtL8UQD6cCU6/tFQipbiGYw4XSeSQjSeqScZjWhkwzu69V6gYWgCeL7BuLqE4BrfgyUVjuGt2CeChhAxOZC8n1McIxxpZ50ST7F1HdWlpjRj1WrlsMLzLH/FaBWo4zqtGQxyg92d28AlwpiLgVIt1pDNt8PgrvHsyjCKhL4Vh373wmSMuiwVbBcG8Rl2x29ek2ot9UP9iZjSnNuC6BSsO9d6FOggKBjE3LjAuMUABWAA=",
   },
}

func Test_Response(t *testing.T) {
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
   for _, test := range tests {
      pssh, err := base64.StdEncoding.DecodeString(test.pssh)
      if err != nil {
         t.Fatal(err)
      }
      mod, err := New_Module(private_key, client_ID, pssh)
      if err != nil {
         t.Fatal(err)
      }
      response, err := base64.StdEncoding.DecodeString(test.response)
      if err != nil {
         t.Fatal(err)
      }
      key, err := mod.signed_response(response)
      if err != nil {
         t.Fatal(err)
      }
      fmt.Printf("%v\n%x\n\n", test.url, key)
   }
}
