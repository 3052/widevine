package dash

import (
   "encoding/base64"
   "encoding/xml"
   "errors"
   "io"
   "strconv"
   "strings"
)

func (r Representer) Widevine() ([]byte, error) {
   for _, c := range r.Content_Protection {
      if c.Scheme_ID_URI == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" {
         return base64.StdEncoding.DecodeString(c.PSSH)
      }
   }
   return nil, errors.New("Widevine Content Protection not found")
}

func Audio(r Representer) bool {
   return *r.MIME_Type == "audio/mp4"
}

func Not[E any](fn func(E) bool) func(E) bool {
   return func(value E) bool {
      return !fn(value)
   }
}

func Video(r Representer) bool {
   return *r.MIME_Type == "video/mp4"
}

func replace(s *string, in, out string) {
   *s = strings.Replace(*s, in, out, 1)
}

// amcplus.com
type Adapter struct {
   Content_Protection []Protecter `xml:"ContentProtection"`
   Lang string `xml:"lang,attr"`
   MIME_Type string `xml:"mimeType,attr"`
   Segment_Template *Template `xml:"SegmentTemplate"`
   Representation []Representer
   Role *struct {
      Value string `xml:"value,attr"`
   }
}

// roku.com
type Protecter struct {
   PSSH string `xml:"pssh"`
   Scheme_ID_URI string `xml:"schemeIdUri,attr"`
}

type Representer struct {
   // roku.com
   Bandwidth int `xml:"bandwidth,attr"`
   // roku.com
   Codecs string `xml:"codecs,attr"`
   // roku.com
   Content_Protection []Protecter `xml:"ContentProtection"`
   // roku.com
   Height int `xml:"height,attr"`
   // roku.com
   ID string `xml:"id,attr"`
   // paramountplus.com
   MIME_Type *string `xml:"mimeType,attr"`
   // roku.com
   Segment_Template *Template `xml:"SegmentTemplate"`
   // roku.com
   Width int `xml:"width,attr"`
   // roku.com
   Adaptation_Set *Adapter
}

func Representers(r io.Reader) ([]Representer, error) {
   var s struct {
      Period struct {
         Adaptation_Set []Adapter `xml:"AdaptationSet"`
      }
   }
   err := xml.NewDecoder(r).Decode(&s)
   if err != nil {
      return nil, err
   }
   var reps []Representer
   for _, ada := range s.Period.Adaptation_Set {
      ada := ada
      for _, rep := range ada.Representation {
         rep := rep
         rep.Adaptation_Set = &ada
         if rep.Content_Protection == nil {
            rep.Content_Protection = ada.Content_Protection
         }
         if rep.MIME_Type == nil {
            rep.MIME_Type = &ada.MIME_Type
         }
         if rep.Segment_Template == nil {
            rep.Segment_Template = ada.Segment_Template
         }
         if rep.Segment_Template != nil {
            rep.Segment_Template.Representation = &rep
         }
         reps = append(reps, rep)
      }
   }
   return reps, nil
}

func (r Representer) Ext() string {
   switch {
   case Audio(r):
      return ".m4a"
   case Video(r):
      return ".m4v"
   }
   return ""
}

func (r Representer) String() string {
   var s []string
   if r.Width >= 1 {
      s = append(s, "width: " + strconv.Itoa(r.Width))
   }
   if r.Height >= 1 {
      s = append(s, "height: " + strconv.Itoa(r.Height))
   }
   if r.Bandwidth >= 1 {
      s = append(s, "bandwidth: " + strconv.Itoa(r.Bandwidth))
   }
   if r.Codecs != "" {
      s = append(s, "codecs: " + r.Codecs)
   }
   s = append(s, "type: " + *r.MIME_Type)
   if r.Adaptation_Set.Role != nil {
      s = append(s, "role: " + r.Adaptation_Set.Role.Value)
   }
   if r.Adaptation_Set.Lang != "" {
      s = append(s, "language: " + r.Adaptation_Set.Lang)
   }
   return strings.Join(s, "\n")
}

// roku.com
type Template struct {
   Initialization string `xml:"initialization,attr"`
   Media string `xml:"media,attr"`
   Representation *Representer 
   Segment_Timeline struct {
      S []struct {
         D int `xml:"d,attr"` // duration
         R int `xml:"r,attr"` // repeat
         T int `xml:"t,attr"` // time
      }
   } `xml:"SegmentTimeline"`
   Start_Number int `xml:"startNumber,attr"`
}

func (t Template) Get_Initialization() string {
   replace(&t.Initialization, "$RepresentationID$", t.Representation.ID)
   return t.Initialization
}

func (t Template) Get_Media() []string {
   var refs []string
   for _, seg := range t.Segment_Timeline.S {
      seg.T = t.Start_Number
      for seg.R >= 0 {
         {
            ref := t.Media
            replace(&ref, "$Number$", strconv.Itoa(seg.T))
            replace(&ref, "$RepresentationID$", t.Representation.ID)
            refs = append(refs, ref)
         }
         t.Start_Number++
         seg.R--
         seg.T++
      }
   }
   return refs
}
