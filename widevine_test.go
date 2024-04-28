package widevine

import (
   "encoding/base64"
   "encoding/hex"
   "os"
)

type tester struct {
   key_id string
   pssh string
   url      string
}

func (t tester) cdm() (*CDM, error) {
   home, err := os.UserHomeDir()
   if err != nil {
      return nil, err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return nil, err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return nil, err
   }
   if t.pssh != "" {
      data, err := base64.StdEncoding.DecodeString(t.pssh)
      if err != nil {
         return nil, err
      }
      return PSSH(data).CDM(client_id, private_key)
   }
   data, err := hex.DecodeString(t.key_id)
   if err != nil {
      return nil, err
   }
   return KeyId(data).CDM(client_id, private_key)
}

var tests = map[string]tester{
   "amc": {
      url:      "amcplus.com/movies/blackberry--1065021",
   },
   "ctv": {
      url:      "ctv.ca/movies/the-girl-with-the-dragon-tattoo-2011",
   },
   "hulu": {
      url:      "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
   },
   "mubi": {
      url:      "mubi.com/en/us/films/the-blair-witch-project",
   },
   "nbc": {
      url:      "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
   },
   "paramount": {
      url:      "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
   },
   "roku": {
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
   },
   "stan": {
      url: "play.stan.com.au/programs/1768588",
   },
}
