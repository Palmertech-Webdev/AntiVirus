package support

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

type SupportBundleService struct{}

func NewSupportBundleService() *SupportBundleService {
	return &SupportBundleService{}
}

// Collect creates a compressed tar archive of diagnostic data.
func (s *SupportBundleService) Collect(destDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	bundleName := fmt.Sprintf("fenrir-support-%s.tar.gz", timestamp)
	bundlePath := filepath.Join(destDir, bundleName)

	f, err := os.Create(bundlePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// Directories to include
	sources := []string{
		"/var/lib/fenrir/evidence",
		"/var/lib/fenrir/quarantine",
		"/var/log/fenrir",
	}

	for _, src := range sources {
		if err := addDirToTar(tw, src); err != nil {
			log.Printf("[Support] Could not add %s: %v", src, err)
		}
	}

	log.Printf("[Support] Bundle created: %s", bundlePath)
	return bundlePath, nil
}

func addDirToTar(tw *tar.Writer, src string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = path
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if !info.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
}
