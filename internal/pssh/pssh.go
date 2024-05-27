package main

import (
   "encoding/base64"
   "encoding/hex"
   "flag"
   "fmt"
   "slices"
)

func prepend(src []byte, i int) string {
   dst := append(make([]byte, i), src...)
   return base64.RawStdEncoding.EncodeToString(dst)[i+1:]
}

func lower(src []byte) string {
   return fmt.Sprintf("%x", src)
}

func double_escape(src []byte) string {
   var dst []byte
   for _, s := range src {
      dst = fmt.Appendf(dst, `\\x%02x`, s)
   }
   return string(dst)
}

func upper(src []byte) string {
   return fmt.Sprintf("%X", src)
}

func dash(src string) string {
   dst := []byte(src)
   dst = slices.Insert(dst, 8, '-')
   dst = slices.Insert(dst, 13, '-')
   dst = slices.Insert(dst, 18, '-')
   dst = slices.Insert(dst, 23, '-')
   return string(dst)
}
func main() {
   base64_id := flag.String("b", "", "base64 ID")
   hex_id := flag.String("h", "", "hex ID")
   flag.Parse()
   data, ok := func() ([]byte, bool) {
      switch {
      case *base64_id != "":
         b, err := base64.StdEncoding.DecodeString(*base64_id)
         if err != nil {
            panic(err)
         }
         return b, true
      case *hex_id != "":
         b, err := hex.DecodeString(*hex_id)
         if err != nil {
            panic(err)
         }
         return b, true
      }
      return nil, false
   }()
   if ok {
      fmt.Println(lower(data))
      fmt.Println(upper(data))
      fmt.Println(dash(lower(data)))
      fmt.Println(dash(upper(data)))
      fmt.Println(prepend(data, 0))
      fmt.Println(prepend(data, 1))
      fmt.Println(prepend(data, 2))
      fmt.Printf("%q\n", data)
      fmt.Println(double_escape(data))
   } else {
      flag.Usage()
   }
}

