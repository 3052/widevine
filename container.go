package widevine

import (
   "154.pages.dev/encoding/protobuf"
   "fmt"
)

var _ = protobuf.Message{
   protobuf.Field{Number: 6, Type: 2, Value: protobuf.Prefix{
      protobuf.Field{Number: 1, Type: 0, Value: protobuf.Varint(0)},
      protobuf.Field{Number: 2, Type: 0, Value: protobuf.Varint(42)},
   }},
   protobuf.Field{Number: 12, Type: 2, Value: protobuf.Bytes("SD")},
}

var _ = protobuf.Message{
   protobuf.Field{Number: 6, Type: 2, Value: protobuf.Prefix{
      protobuf.Field{Number: 1, Type: 0, Value: protobuf.Varint(1)},
      protobuf.Field{Number: 2, Type: 0, Value: protobuf.Varint(3)},
   }},
   protobuf.Field{Number: 12, Type: 2, Value: protobuf.Bytes("UHD1")},
}

var _ = protobuf.Message{
   protobuf.Field{Number: 6, Type: 2, Value: protobuf.Prefix{
      protobuf.Field{Number: 1, Type: 0, Value: protobuf.Varint(0)},
      protobuf.Field{Number: 2, Type: 0, Value: protobuf.Varint(42)},
   }},
   protobuf.Field{Number: 12, Type: 2, Value: protobuf.Bytes("AUDIO")},
}

var _ = protobuf.Message{
   protobuf.Field{Number: 6, Type: 2, Value: protobuf.Prefix{
      protobuf.Field{Number: 1, Type: 0, Value: protobuf.Varint(1)},
      protobuf.Field{Number: 2, Type: 0, Value: protobuf.Varint(3)},
   }},
   protobuf.Field{Number: 12, Type: 2, Value: protobuf.Bytes("HD")},
}

var _ = protobuf.Message{
   protobuf.Field{Number: 6, Type: 2, Value: protobuf.Prefix{
      protobuf.Field{Number: 1, Type: 0, Value: protobuf.Varint(0)},
      protobuf.Field{Number: 2, Type: 0, Value: protobuf.Varint(3)},
   }},
   protobuf.Field{Number: 12, Type: 2, Value: protobuf.Bytes("HD")},
}

type Container struct {
   // bytes Id = 1;
   ID []byte
   // bytes Iv = 2;
   IV []byte
   // bytes Key = 3;
   Key []byte
   // KeyType Type = 4;
   Type uint64
}

type Containers []Container

func (c Containers) Content() *Container {
   for _, container := range c {
      if container.Type == 2 {
         return &container
      }
   }
   return nil
}

func (c Container) String() string {
   return fmt.Sprintf("ID:%x key:%x", c.ID, c.Key)
}
