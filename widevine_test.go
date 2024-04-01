package widevine

import (
   "encoding/hex"
   "os"
)

var tests = map[string]struct {
   key_id string
   url      string
}{
   "amc": {
      key_id: "fdc19f48326e4fe0a17c0a4f0bf9d6fb",
      url:      "amcplus.com/movies/blackberry--1065021",
   },
   "hulu": {
      key_id: "21b82dc2ebb24d5aa9f8631f04726650",
      url:      "hulu.com/watch/023c49bf-6a99-4c67-851c-4c9e7609cc1d",
   },
   "mubi": {
      key_id: "ead55c7d988d4c6c963b292a8397ca0a",
      url:      "mubi.com/en/us/films/the-blair-witch-project",
   },
   "nbc": {
      key_id: "646ec66039ec4372a7484fde9541d99a",
      url:      "nbc.com/saturday-night-live/video/february-3-ayo-edebiri/9000283433",
   },
   "paramount": {
      key_id: "3de0f33c1b8a4fce961edaa950e2e732",
      url:      "paramountplus.com/shows/video/bqsJh_z7o4AR6ktui_9y8wIHqzEEqbhr",
   },
   "peacock": {
      key_id: "0016e23473ebe77d93d8d1a72dc690d7",
      url:      "peacocktv.com/watch/playback/vod/GMO_00000000224510_02_HDSDR",
   },
   "roku": {
      key_id: "bdfa4d6cdb39702e5b681f90617f9a7e",
      url:      "therokuchannel.roku.com/watch/105c41ea75775968b670fbb26978ed76",
   },
   "stan": {
      url: "stan.com.au/watch/a-knights-tale-2001",
      key_id: "94eb4c43cb6a428f8f882b062ce08bbb",
   },
}

func (c *CDM) test(raw_key_id string) error {
   home, err := os.UserHomeDir()
   if err != nil {
      return err
   }
   private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
   if err != nil {
      return err
   }
   client_id, err := os.ReadFile(home + "/widevine/client_id.bin")
   if err != nil {
      return err
   }
   key_id, err := hex.DecodeString(raw_key_id)
   if err != nil {
      return err
   }
   return c.New(private_key, client_id, key_id)
}
