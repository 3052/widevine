package widevine

import "fmt"

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
