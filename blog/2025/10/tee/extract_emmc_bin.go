package main

import (
   "bytes"
   "encoding/binary"
   "flag"
   "fmt"
   "io"
   "log"
   "os"
   "path/filepath"
)

const outputDir = "emmc"

func main() {
   inputFile := flag.String("i", "", "input file")
   flag.Parse()
   if *inputFile == "" {
      flag.Usage()
      return
   }
   if err := createDirectory(outputDir); err != nil {
      log.Fatalf("Could not prepare output directory: %v", err)
   }
   fmt.Println("\nPartitions:\n")
   // 1. Read the header from the input file
   headerFile, err := os.Open(*inputFile)
   if err != nil {
      log.Fatalf("Failed to open input file: %v", err)
   }
   defer headerFile.Close()

   header := make([]byte, HeaderSize)
   n, err := io.ReadFull(headerFile, header)
   if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
      log.Fatalf("Failed to read header from file: %v", err)
   }
   if n < HeaderSize {
      fmt.Printf("Warning: File size is less than header size. Read %d bytes.\n", n)
      header = header[:n] // Truncate header to actual bytes read
   }
   
   // Save the header to a file
   headerPath := filepath.Join(outputDir, "~header")
   if err := os.WriteFile(headerPath, header, 0644); err != nil {
      log.Fatalf("Failed to save header file: %v", err)
   }

   // 2. Find and parse partitions within the header
   var partitions []Partition
   for i := 0; i+DefaultBlockSize <= len(header); i += DefaultBlockSize {
      block := header[i : i+2]
      partitionType := binary.LittleEndian.Uint16(block)

      if partitionType == TypePartition {
         // Extract name, base, and size from the block
         nameBytes := header[i+OffsetName : i+OffsetName+20]
         // Find the null terminator and trim the string
         nullIndex := bytes.IndexByte(nameBytes, 0)
         if nullIndex == -1 {
            nullIndex = len(nameBytes)
         }
         name := string(nameBytes[:nullIndex])

         base := binary.LittleEndian.Uint32(header[i+OffsetBase : i+OffsetBase+4])
         size := binary.LittleEndian.Uint32(header[i+OffsetSize : i+OffsetSize+4])

         // Calculate human-readable size
         fullSizeKB := (int64(size) * DefaultBlockSize) / KB
         var fullSizeStr string
         if fullSizeKB > 1024 {
            fullSizeStr = fmt.Sprintf("%d MB", fullSizeKB/1024)
         } else {
            fullSizeStr = fmt.Sprintf("%d KB", fullSizeKB)
         }
         
         // Print partition info
         partNum := len(partitions) + 1
         baseAndSize := fmt.Sprintf("%d:%d", base, size)
         fmt.Printf("%02d: %-30s %-25s %s\n", partNum, name, baseAndSize, fullSizeStr)
         partitions = append(partitions, Partition{Name: name, Base: base, Size: size})
      }
   }
   
   if len(partitions) < 1 {
      log.Fatal("\nPartitions are not found\n")
   }
   
   fmt.Println("\nExtracting...\n")

   // 3. Extract each partition
   for i, p := range partitions {
      outFile := filepath.Join(outputDir, p.Name+".bin")
      
      infoStr := fmt.Sprintf("%s [%d:%d]", p.Name, p.Base, p.Size)
      fmt.Printf("Saving (%02d/%d) %-40s => %s\n", i+1, len(partitions), infoStr, outFile)
      
      // Calculate offset and size in bytes using int64 to avoid overflow
      offsetBytes := int64(p.Base) * DefaultBlockSize
      sizeBytes := int64(p.Size) * DefaultBlockSize
      err = copyPart(*inputFile, outFile, offsetBytes, sizeBytes)
      if err != nil {
         log.Printf("ERROR: Failed to extract partition %s: %v", p.Name, err)
      }
   }
}

// Constants defined in the Python script
const (
   B  = 1 << (10 * 0) // 2^0
   KB = 1 << (10 * 1) // 2^10
   MB = 1 << (10 * 2) // 2^20
   GB = 1 << (10 * 3) // 2^30

   DefaultBlockSize = 512
   HeaderSize       = 2 * MB // Header size is always 2MB

   TypePartition = 22592 // Magic number to identify a partition entry

   OffsetName = 0x10
   OffsetBase = 0x08
   OffsetSize = 0x0C
)

type Partition struct {
   Name string
   Base uint32 // Base address in blocks
   Size uint32 // Size in blocks
}

func createDirectory(dir string) error {
   // Check if directory exists
   if _, err := os.Stat(dir); os.IsNotExist(err) {
      // It doesn't exist, so create it
      if err := os.MkdirAll(dir, 0755); err != nil {
         return fmt.Errorf("failed to create directory %s: %w", dir, err)
      }
   } else if err == nil {
      // It exists, so clear its contents
      files, err := os.ReadDir(dir)
      if err != nil {
         return fmt.Errorf("failed to read directory %s for clearing: %w", dir, err)
      }
      for _, file := range files {
         filePath := filepath.Join(dir, file.Name())
         if err := os.RemoveAll(filePath); err != nil {
            return fmt.Errorf("failed to remove file %s: %w", filePath, err)
         }
      }
   } else {
      // Some other error occurred when checking the directory
      return fmt.Errorf("failed to stat directory %s: %w", dir, err)
   }
   return nil
}

// copyPart copies a portion of a source file to a destination file.
// It uses io.CopyN for efficient, buffered copying.
func copyPart(srcPath, destPath string, offset int64, size int64) error {
   srcFile, err := os.Open(srcPath)
   if err != nil {
      return fmt.Errorf("could not open source file %s: %w", srcPath, err)
   }
   defer srcFile.Close()
   if _, err := srcFile.Seek(offset, io.SeekStart); err != nil {
      return fmt.Errorf("could not seek in source file %s to offset %d: %w", srcPath, offset, err)
   }
   destFile, err := os.Create(destPath)
   if err != nil {
      return fmt.Errorf("could not create destination file %s: %w", destPath, err)
   }
   defer destFile.Close()
   written, err := io.CopyN(destFile, srcFile, size)
   if err != nil {
      return fmt.Errorf("error copying data from %s to %s: %w", srcPath, destPath, err)
   }
   if written != size {
      return fmt.Errorf("expected to write %d bytes, but only wrote %d", size, written)
   }
   return nil
}
