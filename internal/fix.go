package main

import (
   "154.pages.dev/protobuf"
   "bytes"
   "os"
)

func main() {
   data, err := os.ReadFile("req.txt")
   if err != nil {
      panic(err)
   }
   _, data, _ = bytes.Cut(data, []byte("\r\n\r\n"))
   var message protobuf.Message
   if err := message.Consume(data); err != nil {
      panic(err)
   }
   file, err := os.Create("peacock.go")
   if err != nil {
      panic(err)
   }
   defer file.Close()
   file.WriteString("package main\n")
   file.WriteString("import `154.pages.dev/protobuf`\n")
   file.WriteString("var message = ")
   file.WriteString(message.GoString())
}
