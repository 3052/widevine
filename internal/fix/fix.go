package main

import (
   "154.pages.dev/protobuf"
   "bufio"
   "fmt"
   "io"
   "net/http"
   "os"
)

func main() {
   req, err := func() (*http.Request, error) {
      f, err := os.Open("req.txt")
      if err != nil {
         return nil, err
      }
      defer f.Close()
      return http.ReadRequest(bufio.NewReader(f))
   }()
   if err != nil {
      panic(err)
   }
   body, err := io.ReadAll(req.Body)
   if err != nil {
      panic(err)
   }
   var message protobuf.Message
   if err := message.Consume(body); err != nil {
      panic(err)
   }
   message, _ = message.Get(2)
   f, err := os.Create("peacock.go")
   if err != nil {
      panic(err)
   }
   defer f.Close()
   fmt.Fprintln(f, "package main")
   fmt.Fprintln(f, `import "154.pages.dev/protobuf"`)
   fmt.Fprintf(f, "var address = %q\n", req.URL.RawQuery)
   fmt.Fprintln(f, "var message =", message.GoString())
}
