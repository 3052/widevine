package main

import "strconv"

type client_info struct {
   DrmVersion          *string
   HdcpSupport         string
   Manufacturer        string
   Model               string
   SecLevel            int64
   VmpStatus           string
   VrConstraintSupport bool
}

func (c *client_info) String() string {
   var data []byte
   if c.DrmVersion != nil {
      data = append(data, "drmVersion = "...)
      data = append(data, *c.DrmVersion...)
   }
   if data != nil {
      data = append(data, '\n')
   }
   data = append(data, "hdcpSupport = "...)
   data = append(data, c.HdcpSupport...)
   data = append(data, "\nmanufacturer = "...)
   data = append(data, c.Manufacturer...)
   data = append(data, "\nmodel = "...)
   data = append(data, c.Model...)
   data = append(data, "\nsecLevel = "...)
   data = strconv.AppendInt(data, c.SecLevel, 10)
   data = append(data, "\nvmpStatus = "...)
   data = append(data, c.VmpStatus...)
   data = append(data, "\nvrConstraintSupport = "...)
   data = strconv.AppendBool(data, c.VrConstraintSupport)
   return string(data)
}
