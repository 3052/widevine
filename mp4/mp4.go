package mp4

import (
   "github.com/Eyevinn/mp4ff/mp4"
   "io"
)

// progress is only needed after Init, so keep io.Writer out of the type
type Decrypt map[uint32]*mp4.SinfBox

func (d Decrypt) Init(r io.Reader, w io.Writer) error {
   file, err := mp4.DecodeFile(r)
   if err != nil {
      return err
   }
   // need for VLC media player
   for _, trak := range file.Init.Moov.Traks {
      for _, child := range trak.Mdia.Minf.Stbl.Stsd.Children {
         switch box := child.(type) {
         case *mp4.AudioSampleEntryBox:
            d[trak.Tkhd.TrackID], err = box.RemoveEncryption()
         case *mp4.VisualSampleEntryBox:
            d[trak.Tkhd.TrackID], err = box.RemoveEncryption()
         }
         if err != nil {
            return err
         }
      }
   }
   // need for Mozilla Firefox
   file.Init.Moov.RemovePsshs()
   return file.Init.Encode(w)
}

func (d Decrypt) Segment(r io.Reader, w io.Writer, key []byte) error {
   file, err := mp4.DecodeFile(r)
   if err != nil {
      return err
   }
   for _, seg := range file.Segments {
      for _, frag := range seg.Fragments {
         var removed uint64
         for _, traf := range frag.Moof.Trafs {
            sinf := d[traf.Tfhd.TrackID]
            if sinf == nil {
               continue
            }
            samples, err := frag.GetFullSamples(nil)
            if err != nil {
               return err
            }
            tenc := sinf.Schi.Tenc
            for i, sample := range samples {
               iv := tenc.DefaultConstantIV
               if iv == nil {
                  iv = append(iv, traf.Senc.IVs[i]...)
                  iv = append(iv, 0, 0, 0, 0, 0, 0, 0, 0)
               }
               var sub []mp4.SubSamplePattern
               if len(traf.Senc.SubSamples) > i {
                  // required for playback
                  sub = traf.Senc.SubSamples[i]
               }
               switch sinf.Schm.SchemeType {
               case "cenc":
                  err = mp4.DecryptSampleCenc(sample.Data, key, iv, sub)
               case "cbcs":
                  err = mp4.DecryptSampleCbcs(sample.Data, key, iv, sub, tenc)
               }
               if err != nil {
                  return err
               }
            }
            // required for playback
            removed += traf.RemoveEncryptionBoxes()
         }
         // fast start
         _, pssh := frag.Moof.RemovePsshs()
         removed += pssh
         for _, traf := range frag.Moof.Trafs {
            for _, trun := range traf.Truns {
               // required for playback
               trun.DataOffset -= int32(removed)
            }
         }
      }
      // fix jerk between fragments
      seg.Sidx = nil
      err := seg.Encode(w)
      if err != nil {
         return err
      }
   }
   return nil
}
