package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const (
	currentVersion   = "1.0.0"
	githubReleaseAPI = "https://api.github.com/repos/AntiVirus/fenrir/releases/latest"
)

type GithubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type UpdaterService struct {
	httpClient *http.Client
}

func NewUpdaterService() *UpdaterService {
	return &UpdaterService{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// CheckForUpdate queries GitHub for the latest release.
func (u *UpdaterService) CheckForUpdate() (*GithubRelease, bool, error) {
	req, _ := http.NewRequest("GET", githubReleaseAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	var release GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, false, fmt.Errorf("decode release: %w", err)
	}

	latest := release.TagName
	if latest == "v"+currentVersion || latest == currentVersion {
		return &release, false, nil
	}

	log.Printf("[Updater] New version available: %s (current: %s)", latest, currentVersion)
	return &release, true, nil
}

// DownloadAndApply downloads the matching asset and hot-swaps the binary.
func (u *UpdaterService) DownloadAndApply(release *GithubRelease) error {
	assetName := fmt.Sprintf("fenrir-linux-agent-%s", runtime.GOARCH)
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no matching asset found for %s", assetName)
	}

	tmpPath := "/tmp/fenrir-update"
	if err := u.download(downloadURL, tmpPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return err
	}

	selfPath, _ := os.Executable()
	backupPath := selfPath + ".bak"

	if err := os.Rename(selfPath, backupPath); err != nil {
		return fmt.Errorf("backup self: %w", err)
	}
	if err := os.Rename(tmpPath, selfPath); err != nil {
		os.Rename(backupPath, selfPath)
		return fmt.Errorf("swap binary: %w", err)
	}

	log.Printf("[Updater] Updated to %s. Restarting via systemctl...", release.TagName)
	exec.Command("systemctl", "restart", "fenrir").Start()
	return nil
}

func (u *UpdaterService) download(url, dest string) error {
	resp, err := u.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
