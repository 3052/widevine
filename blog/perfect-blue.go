package main

import (
   "154.pages.dev/encoding/protobuf"
   "encoding/base64"
   "fmt"
   "slices"
)

const perfect_blue = "CAISlQUKLgoAEiYKEJ/rB4ZCLEyVn6XTC+W3Nv8QATIQOlZidDX8oP4f+vmjvE8T8CABKAASGggBEAAYACAAKAA4AEIASABQAFgAYAFwAHgAGkYSEMCmKfvJNXnbGzNp0C3r4NAaMIs+rLPSBpQSq0TCJQsoGUo09csN5gUOhzhJRUnt9E0qOwVbHN4yEp2mw5d+hkgfpSABGmIKEHeNbXayhEk6piZyx2Yif58SENf+WiQGUzNjNocT2HbvbYkaICBC4HiS//GVEMGo724evKinuvU89HJ6tFwszHhiHSGEIAIoATIICAAQKhgAIAA6CAgAECoYACAAYgJTRBpkChCpRhFtg8xPbLyJN9H0L4/oEhCq9Y6IrxDj3xTtwILguoKYGiA3FGSNeYR4kSPKoVQ2csRFbld4Sfaetm49+set8xtkRiACKAEyCAgBEAMYACAAOggIABAqGAAgAGIEVUhEMRplChCVfhTPb/hF6ZInvPHzNEw+EhA3tbzVVism8VjFKZU+juMgGiA90JHmKATDEzazT5xrrnQNPh4kgAS6j1ajPu9qNry6piACKAEyCAgAECoYACAAOggIABAqGAAgAGIFQVVESU8aYgoQC/ymvo2ETa+XnK+6qXy5nRIQpStUxZGB4ihGz4mLjYuDzxogL50JqgtaPt1O8ANCofYRmRYkKpNQ6tyjdSWdEUqkCdMgAigBMggIARADGAAgADoICAAQKhgAIABiAkhEGmIKECMh14jAKkG1pWXOBwRyAJgSEJN9Biw3JbFe7GJI6r8VQRwaIGUq3SuFEK29jRjzvHI9GJwwF1QvG7HbFgZLBlqNFtCOIAIoATIICAAQAxgAIAA6CAgAECoYACAAYgJIRCDJ8/SnBjgAGiBIOSjkKTnfLSzl/h1ZMZCEJir+3xljpOGMERedNMKG6iKAAgLgSQZ2i8Tu1RfovWDdDuOf67wdayidfeSG4+fBOmdNIg6CsqBE7VCSzP68FdiDxm6TPAdo7x5Uf4wtIs++MDB/cRKwtWbvtMyyyUxOAz/795I6DEe16t4PI3nbEvdos5XSgHXdtpiJz7PC1EULbz/IClMqNtfnsPqozNn8eENxR+nxdXmQzEuV7LnIlNi0E5GctsPRT46Bav1gLD5yNusqiBkQ+3j2kriG9I1N9yuUwm9c5HZAckdv7/Hr8jJeFALC7kC7jByUeC0yHrd/AuuJ/WcDr7QE5CYo1BnVNEvFOmAbjaguYul5JVnKCcJH8Q/rkWRv4rZY4vasWDufrTs6CAoGMTguMC4xQAFYAA=="

func main() {
   data, err := base64.StdEncoding.DecodeString(perfect_blue)
   if err != nil {
      panic(err)
   }
   signed_message, err := protobuf.Consume(data)
   if err != nil {
      panic(err)
   }
   if license, ok := signed_message.Message(2); ok {
      i := slices.IndexFunc(license, func(f protobuf.Field) bool {
         if f.Number == 3 {
            if m, ok := f.Message(); ok {
               if s, ok := m.String(12); ok {
                  if s == "AUDIO" {
                     return true
                  }
               }
            }
         }
         return false
      })
      fmt.Printf("%#v\n", license[i])
   }
}
