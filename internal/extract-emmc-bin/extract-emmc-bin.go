package main

import (
   "bufio"
   "encoding/binary"
   "fmt"
   "io"
   "log"
   "os"
   "path/filepath"
   "strconv"
   "strings"
)

// VARS
const (
   B             = 1 << 0
   KB            = 1 << 10
   MB            = 1 << 20
   GB            = 1 << 30
   HEADERSIZE    = 2 * MB // Header size is always 2MB
   TYPEPARTITION = 22592
   OFFSETNAME    = 0x10
   OFFSETBASE    = 0x08
   OFFSETSIZE    = 0x0C
)

var BLOCKSIZE int64 = 0x200

// Partition struct to hold partition information
type Partition struct {
   Name string
   Base int64
   Size int64
}

// createDirectory ensures a directory exists and is empty.
func createDirectory(dir string) {
   if _, err := os.Stat(dir); os.IsNotExist(err) {
      if err := os.MkdirAll(dir, 0755); err != nil {
         log.Fatalf("Failed to create directory: %v", err)
      }
   } else {
      files, err := os.ReadDir(dir)
      if err != nil {
         log.Fatalf("Failed to read directory: %v", err)
      }
      for _, file := range files {
         filePath := filepath.Join(dir, file.Name())
         if err := os.Remove(filePath); err != nil {
            log.Printf("Failed to remove file: %v", err)
         }
      }
   }
}

// =================================================================
// UPDATED copyPart FUNCTION
// It now accepts an already-open file handle (*os.File)
// =================================================================
func copyPart(srcFile *os.File, dest string, offset int64, size int64) {
   // Seek to the correct offset for the partition in the source file
   if _, err := srcFile.Seek(offset, io.SeekStart); err != nil {
      log.Fatalf("Failed to seek in source file: %v", err)
   }

   // Create the destination file for the partition
   destFile, err := os.Create(dest)
   if err != nil {
      log.Fatalf("Failed to create destination file: %v", err)
   }
   defer destFile.Close()

   // Use io.Copy with an io.LimitReader to efficiently copy the exact number of bytes
   if _, err := io.Copy(destFile, io.LimitReader(srcFile, size)); err != nil {
      log.Fatalf("Failed to copy data: %v", err)
   }
}

func main() {
   var inputFile string
   var outputDirectory = "emmc"

   if len(os.Args) < 2 {
      fmt.Println("Usage: unpack <emmc.bin> <block size [default: 512]> <output folder [default: ./emmc/]>")
      fmt.Print("Do you want open disk? (choose letter): ")
      reader := bufio.NewReader(os.Stdin)
      disk, _ := reader.ReadString('\n')
      disk = strings.TrimSpace(disk)
      fmt.Println()

      if len(disk) == 1 {
         inputFile = `\\.\` + strings.ToUpper(disk) + ":"
      } else {
         fmt.Println("Nothing to do - exiting")
         return
      }
   } else {
      inputFile = os.Args[1]
   }

   if len(os.Args) >= 3 {
      bs, err := strconv.ParseInt(os.Args[2], 10, 64)
      if err != nil {
         log.Fatalf("Invalid block size: %v", err)
      }
      BLOCKSIZE = bs
   }

   if len(os.Args) == 4 {
      outputDirectory = os.Args[3]
   }

   createDirectory(outputDirectory)

   // =================================================================
   // IMPROVEMENT: Open the source file ONCE here
   // =================================================================
   srcFile, err := os.Open(inputFile)
   if err != nil {
      log.Fatalf("Failed to open input file %s: %v", inputFile, err)
   }
   // Ensure the file is closed when the program exits
   defer srcFile.Close()

   if strings.HasPrefix(inputFile, `\\.\`) {
      fmt.Printf("Direct disk read mode - %s\n", inputFile)
   } else {
      fileInfo, err := srcFile.Stat()
      if err != nil {
         log.Fatalf("Failed to get file info: %v", err)
      }
      fmt.Printf("\nFile size:  %d Bytes\n", fileInfo.Size())
   }

   fmt.Printf("Block size: %d Bytes\n", BLOCKSIZE)
   fmt.Println("\nPartitions:\n")

   // Read the header from the already-open file
   header := make([]byte, HEADERSIZE)
   if _, err := srcFile.ReadAt(header, 0); err != nil {
      log.Fatalf("Failed to read header: %v", err)
   }
   
   // Save the header file
   copyPart(srcFile, filepath.Join(outputDirectory, "~header"), 0, HEADERSIZE)


   var partitions []Partition
   for x := 0; x < len(header); x += int(BLOCKSIZE) {
      partitionType := binary.LittleEndian.Uint16(header[x : x+2])
      if partitionType == TYPEPARTITION {
         nameBytes := header[x+OFFSETNAME : x+OFFSETNAME+20]
         name := strings.TrimRight(string(nameBytes), "\x00")
         base := binary.LittleEndian.Uint32(header[x+OFFSETBASE : x+OFFSETBASE+4])
         size := binary.LittleEndian.Uint32(header[x+OFFSETSIZE : x+OFFSETSIZE+4])
         fullSize := int64(size) * BLOCKSIZE / 1024
         var fullSizeStr string
         if fullSize > 1024 {
            fullSizeStr = fmt.Sprintf("%d MB", fullSize/1024)
         } else {
            fullSizeStr = fmt.Sprintf("%d KB", fullSize)
         }
         fmt.Printf("%02d: %-30s %-25s %s\n", len(partitions)+1, name, fmt.Sprintf("%d:%d", base, size), fullSizeStr)
         partitions = append(partitions, Partition{Name: name, Base: int64(base), Size: int64(size)})
      }
   }

   if len(partitions) < 1 {
      fmt.Println("\nPartitions are not found")
      return
   }

   fmt.Println("\nExtracting...\n")

   for i, p := range partitions {
      outFile := filepath.Join(outputDirectory, p.Name+".bin")
      fmt.Printf("Saving (%02d/%d) %-40s => %s\n", i+1, len(partitions), fmt.Sprintf("%s [%d:%d]", p.Name, p.Size, p.Base), outFile)
      // =================================================================
      // Pass the open file handle, not the filename string
      // =================================================================
      copyPart(srcFile, outFile, p.Base*BLOCKSIZE, p.Size*BLOCKSIZE)
   }
}
