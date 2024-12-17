package main

import (
   "41.neocities.org/protobuf"
   "encoding/base64"
   "net/http"
   "net/url"
   "os"
)

func main() {
   var req http.Request
   req.Header = http.Header{}
   req.Header["Accept-Language"] = []string{"en-US,en;q=0.9"}
   req.Header["Content-Length"] = []string{"0"}
   req.Header["Content-Type"] = []string{"application/json"}
   req.Header["User-Agent"] = []string{"Widevine CDM v1.0"}
   req.Method = "POST"
   req.ProtoMajor = 1
   req.ProtoMinor = 1
   req.URL = &url.URL{}
   req.URL.Host = "www.googleapis.com"
   req.URL.Path = "/certificateprovisioning/v1/devicecertificates/create"
   value := url.Values{}
   value["key"] = []string{"AIzaSyB-5OLKTx2iU5mko18DfdwK5611JIjbUhE"}
   value["signedRequest"] = []string{
      base64.RawURLEncoding.EncodeToString(message.Marshal()),
   }
   req.URL.RawQuery = value.Encode()
   req.URL.Scheme = "https"
   resp, err := http.DefaultClient.Do(&req)
   if err != nil {
      panic(err)
   }
   defer resp.Body.Close()
   resp.Write(os.Stdout)
}

var message = protobuf.Message{
   1: {protobuf.Message{
      1: {protobuf.Message{
         1: {protobuf.Varint(0)},
         2: {protobuf.Bytes("\x00\x00\x00\x02\x00\x00\x11pΑ\xac\xb5\x98\x15\xeb\x85\x1ag\xa0O]\xc8\x19\xf4 \xf6B\x06\x1c\xc9\xcdC\x852B(\xbb\n\xbd\xe2\xbdO\xa7\x985\xe0\xeb\x16\x92\x06,8\xa4\x1f\xe0\xcd+\xcfxx\x81\x97\xcc\xd1\xdb\xfd\xfdV:'\xb0\xbf")},
      }},
      2: {protobuf.Bytes("\xd0\\I\xda")},
      3: {protobuf.Bytes("\b\x00\x12\x00")},
      4: {protobuf.Bytes("NOLmJBYaaOvklEWzaLhtjbMvLXKQEqs\x00DC2D78B53DC4D820771A314C56FBBED9")},
   }},
   2: {protobuf.Bytes("\xae\xdb,Y\xf9\x16\xc3:\xbdP\x9a\xea\x01\x0e\x96\xeaƁ¨\\\xe32\xc2| \n\xbb,\xeeU\xd1")},
}
