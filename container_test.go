package widevine

import (
   "fmt"
   "testing"
)

var test_container = Container{
   IV:[]uint8{
      0x52, 0x46, 0x8f, 0x90, 0x8c, 0x9f, 0xc7, 0xc6,
      0xe9, 0x96, 0xcc, 0x84, 0x83, 0x6d, 0x58, 0x2a,
   },
   Key:[]uint8{
      0xe2, 0x58, 0xb6, 0x7d, 0x75, 0x42, 0x0, 0x66,
      0xc8, 0x42, 0x4b, 0xd1, 0x42, 0xf8, 0x45, 0x65,
   },
}

func Test_Container(t *testing.T) {
   fmt.Println(test_container)
}