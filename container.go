package widevine

import "fmt"

// IV:Key
func (c Container) String() string {
   return fmt.Sprintf("%x:%x", c.IV, c.Key)
}

type Container struct {
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
