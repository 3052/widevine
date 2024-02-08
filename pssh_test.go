package widevine

import (
   "encoding/base64"
   "fmt"
   "testing"
)

var tests = map[string]struct{
   key_id string
   pssh string
   response string
   url string
}{
   "amcplus": {
      url:      "amcplus.com/movies/perfect-blue--1058032",
      pssh:     "AAAAVnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADYIARIQd41tdrKESTqmJnLHZiJ/nxoNd2lkZXZpbmVfdGVzdCIIMTIzNDU2NzgyB2RlZmF1bHQ=",
      response: "CAISlQUKLgoAEiYKEJ/rB4ZCLEyVn6XTC+W3Nv8QATIQOlZidDX8oP4f+vmjvE8T8CABKAASGggBEAAYACAAKAA4AEIASABQAFgAYAFwAHgAGkYSEMCmKfvJNXnbGzNp0C3r4NAaMIs+rLPSBpQSq0TCJQsoGUo09csN5gUOhzhJRUnt9E0qOwVbHN4yEp2mw5d+hkgfpSABGmIKEHeNbXayhEk6piZyx2Yif58SENf+WiQGUzNjNocT2HbvbYkaICBC4HiS//GVEMGo724evKinuvU89HJ6tFwszHhiHSGEIAIoATIICAAQKhgAIAA6CAgAECoYACAAYgJTRBpkChCpRhFtg8xPbLyJN9H0L4/oEhCq9Y6IrxDj3xTtwILguoKYGiA3FGSNeYR4kSPKoVQ2csRFbld4Sfaetm49+set8xtkRiACKAEyCAgBEAMYACAAOggIABAqGAAgAGIEVUhEMRplChCVfhTPb/hF6ZInvPHzNEw+EhA3tbzVVism8VjFKZU+juMgGiA90JHmKATDEzazT5xrrnQNPh4kgAS6j1ajPu9qNry6piACKAEyCAgAECoYACAAOggIABAqGAAgAGIFQVVESU8aYgoQC/ymvo2ETa+XnK+6qXy5nRIQpStUxZGB4ihGz4mLjYuDzxogL50JqgtaPt1O8ANCofYRmRYkKpNQ6tyjdSWdEUqkCdMgAigBMggIARADGAAgADoICAAQKhgAIABiAkhEGmIKECMh14jAKkG1pWXOBwRyAJgSEJN9Biw3JbFe7GJI6r8VQRwaIGUq3SuFEK29jRjzvHI9GJwwF1QvG7HbFgZLBlqNFtCOIAIoATIICAAQAxgAIAA6CAgAECoYACAAYgJIRCDJ8/SnBjgAGiBIOSjkKTnfLSzl/h1ZMZCEJir+3xljpOGMERedNMKG6iKAAgLgSQZ2i8Tu1RfovWDdDuOf67wdayidfeSG4+fBOmdNIg6CsqBE7VCSzP68FdiDxm6TPAdo7x5Uf4wtIs++MDB/cRKwtWbvtMyyyUxOAz/795I6DEe16t4PI3nbEvdos5XSgHXdtpiJz7PC1EULbz/IClMqNtfnsPqozNn8eENxR+nxdXmQzEuV7LnIlNi0E5GctsPRT46Bav1gLD5yNusqiBkQ+3j2kriG9I1N9yuUwm9c5HZAckdv7/Hr8jJeFALC7kC7jByUeC0yHrd/AuuJ/WcDr7QE5CYo1BnVNEvFOmAbjaguYul5JVnKCcJH8Q/rkWRv4rZY4vasWDufrTs6CAoGMTguMC4xQAFYAA==",
   },
   "hulu": {
      url: "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
      response: "CAIS/QEKcAoAEmhZMlZyYzE4eU1XSTRNbVJqTWkxbFltSXlMVFJrTldFdFlUbG1PQzAyTXpGbU1EUTNNalkyTlRCZlpqUTBPREZtWVdZdE1UZ3hOeTAwWldGakxXSmtOREl0WkRJd09UVmhNR0ppTnpOayABKAASHwgBEAAYACAAKAAwADgAQgBIAFAAWABgAHABeAGAAQAaYAoQIbgtwuuyTVqp+GMfBHJmUBIQVSzS8/YjgQhS9AhekQ/OcxogOPxWn9Kk85jCP3wfhTSzFGEd9PpI5zGXYFuZxJMheQUgAigBMggIABAqGAAgADoICAAQKhgAIABiACCck4yuBjgAGiC4jNOnx+o0bfpiQt1ahNa36AHg7gyg4oj8rdDnaqZgbiKAAmkFYQu3okcULDh55VyDh1ivMXJQx9O5BiL6+YBuT9wcpVbh31arJJ/L3Ls9wtPPtpn68oaoIVmoWtEaocArRvEA3/PsxPD35uviHPoCSmcewp/X5tJqYxJ5rXjooCNz56uarfQ3FB1oDeiuiowSur9uw4piZV338iTUxkl/mWSt+k2/eQTAhXam6nUS+OsPNurdeMbaCPeuzgQkmWVdnzum/Zu2Lbbe1jq0D8YwkJ8r55fEm/XA3ygtwlH+QEWRYOBCzRUDrqX/PQkNyIyb3UnHZp6vwuO45PktkaSQz1kApd/5LJ56l0FYVolwt0+ATaFSl7vEcP3YFRR4UYgXh2U6CAoGMTguMS4yQAFYAA==",
   },
   "nbc": {
      url: "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
      pssh: "AAAAV3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADcIARIQ/zFt5li1T7C00hLL9vmivhoLYnV5ZHJta2V5b3MiEP8xbeZYtU+wtNISy/b5or4qAkhE",
      response: "CAISqgEKIgoAEhAA+Ul+JOc/Q4PJMsuCVv0wIAEoADgAQABI+JWMrgYSHAgBEAAYACAAKAAwADgAQgBIAFAAWABgAHAAeAEaXgoQ/zFt5li1T7C00hLL9vmivhIQLow1+azT1ejZFeDyPMlFrhogBsXtujDeqX0i8FcAmK55sclSVpZgxBChZPtvmrBSgG4gAigBMggIABAqGAAgADoICAAQKhgAIAAg+JWMrgY4ABoglxNFfSrPIJoSQKJ5mqDy1HSXuVkwGz8ap7x72URDTJwigAJmEHqN+3Q/atdGEEhVAm3WQMSnGjMgptbaow09ZFFCs/laxG+cuqo71NOKRMBXHRr/Tdba+YzciOB1U4r8Jj2C/qFEFc5jzWGIp372/RMGzpdjFPb3+/TB8adUN6UhjdiR8mv+588BP71SYl6H1e2Ko4y5/OosH1rZS3A2sFsM4Dhqigmk5EysjhNo4HiJCLNhgbnV65pluwPWvXRhf52r5RP9xa2Rnz+leg7EEcfamSI1RtfhaFHpkWbdpGcJVjiRx/Kfp47kRjWlTXy4+ENkgK0f/ggqH5+mAa7jYo1ZnXiP9dip6iCBrbE1lpV3CWS1+lezcnlV/Df3AvYwgUxaOggKBjE2LjQuNEABWAA=",
   },
   "paramountplus": {
      url: "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
      pssh: "AAAAWHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADgIARIQPeDzPBuKT86WHtqpUOLnMiIgYnFzSmhfejdvNEFSNmt0dWlfOXk4d0lIcXpFRXFiaHI4AQ==",
      response: "CAIS6gEKGgoAEgil3tdjPdud9yABKAA4AEAASOmWjK4GEhwIARAAGAAgACgAMAA4AEIASABQAFgAYAFwAHgBGkYSEOPNAFB8t/OAlRSOn0e4C+waMHogf9DJWujs7wUI6qMoqRSb/PhwXR09EwOrusdXraftU3OftIvJgY88uxLkGYwMyCABGl4KED3g8zwbik/Olh7aqVDi5zISEJJ0VK5hV2dcl3pkh5MGv24aIBFLAWKOF05UdzsJ6nt6kiqxLr5mGMu9LbmP7O0MXr7CIAIoATIICAAQKhgAIAA6CAgAECoYACAAIOmWjK4GOAAaIKcLhXstis/9o8Eo+bnQHmeEEjeWMSWtdxJk5GqHN57UIoACQY/tJvK+dumFlxvu7fkD8nUSE04Ral8xZgv0NVZxWHkr+MxqLnbsW0ZY7aEXvo5tTOCNUG2K1jjGYrLxK4XTJ5cebJJZzdwUmzXNrKVlqlcyULFBdKxHVesgcUVngOtyqeHXmTdZG8eFzx6FgPfis09LUekohWBWxqJcfuBxbA95EnGbV05Xrj3bDL1KQSE/Tw2N7h5ASBnJ0qSsnj1HhIRjPO2+mTXhlJ5UEZL5of1LnQMpGsFJJcrnMN9b2kQRoWEGPloi2hxPJd4AQtaZI507H+xn+w627XnI1xemTrIZZwj16d8gdFfDj+oBKqCOqmGjrCzJCxXjeGEWifShhjoICgYxNy40LjBAAVgA",
   },
   "roku": { // 2023-11-14 this requires content_id, so PSSH is needed:
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
      pssh:     "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQvfpNbNs5cC5baB+QYX+afhoKaW50ZXJ0cnVzdCIBKg==",
      response: "CAISpAEKGgoAEghBPi3uL18dhiABKAA4AEAASOrh758GEh4IARAAGAAgACgAMMnFCjgAQgBIAFAAWABgAHAAeAEaXgoQvfpNbNs5cC5baB+QYX+afhIQUkaPkIyfx8bplsyEg21YKhogQYRNMicID9i4twGGFm/fdKEmJGUVQuNnBXXfUtmYXH4gAigBMggIABAqGAAgADoICAAQKhgAIAAg6uHvnwY4ABoga0R69yOAW/lmax2ng2W92p0JzaIz+GNvKhgucUFs0qsigAKU3+gmgfhY4c6YXXDpAi5lt192PUBfXUCJ6WX+zu3haUI1sY9VxA389iUQ470xm6SW5mF2vcFg7NUeCFEeq+Y15GgZnN9JuLWOq7GQIqsQioLpKvQMIwEamd/KP16KtL8UQD6cCU6/tFQipbiGYw4XSeSQjSeqScZjWhkwzu69V6gYWgCeL7BuLqE4BrfgyUVjuGt2CeChhAxOZC8n1McIxxpZ50ST7F1HdWlpjRj1WrlsMLzLH/FaBWo4zqtGQxyg92d28AlwpiLgVIt1pDNt8PgrvHsyjCKhL4Vh373wmSMuiwVbBcG8Rl2x29ek2ot9UP9iZjSnNuC6BSsO9d6FOggKBjE3LjAuMUABWAA=",
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
         fmt.Printf("%q\n", protect.content_id)
      }
   }
}
