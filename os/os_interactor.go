package os

import (
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// DefaultInteractor is the default OS interactor that wraps go standard os
// package functionality to satisfy different interfaces
type DefaultInteractor struct{}

// OpenURL opens the passed in url in the default OS browser
func (i *DefaultInteractor) OpenURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args, url = i.BuildWindowsAgsAndURL(url)
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		if i.IsWSL() {
			cmd = "cmd.exe"
			args, url = i.BuildWindowsAgsAndURL(url)
		} else {
			cmd = "xdg-open"
		}
	}

	args = append(args, url)

	return exec.Command(cmd, args...).Start()
}

// GetCurrentExecutableLocation returns the location of the currently
// executing binary
func (i DefaultInteractor) GetCurrentExecutableLocation() string {
	loc, err := os.Executable()
	if err != nil {
		panic(err)
	}

	return loc
}

// GetHomeDirAbsolutePath returns the absolute path of the current users home
// directory
func (i DefaultInteractor) GetHomeDirAbsolutePath() string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	return usr.HomeDir
}

// DoesPathExist returns a boolean as to whether the passed in path exists or
// not
func (i DefaultInteractor) DoesPathExist(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// CreateAbsoluteFolderPath creates the passed in path as a directory
func (i DefaultInteractor) CreateAbsoluteFolderPath(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}

// CopyFile copies the source file to the destination file preserving
// permissions
func (i DefaultInteractor) CopyFile(source, destination string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	sourceStat, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	destFile, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_RDWR, sourceStat.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}
	return destFile.Close()
}

// IsWSL runs the "uname -a" command to see if the output contains "microsoft" and returns true if it does, else false.
// This is so we can check if the Linux OS is actually Windows SubSystem for Linux, which requires
// A different command to open a browser.
func (i DefaultInteractor) IsWSL() bool {
	b, err := exec.Command("uname", "-a").Output()
	if err != nil {
		panic(err)
	}

	if strings.Contains(strings.ToLower(string(b)), "microsoft") {
		return true
	}

	return false
}

// BuildWindowsAgsAndURL builds the command args and escapes the url for the Windows command to open a browser.
// The character & is treated as running a separate command in Windows
// cmd /c start "http://domain.com?param1&param2" results in trying to run cmd /c "start http://domain.com?parm1" & param2
// Also, the " char is used as the delimiter to escape special characters, so "&" would become \&\
// cmd /c start 'http://domain.com?param1=value with space"&"param2=value2' works when inputting directly to the command prompt,
// but the "&" is escaped by \"&\" when passed from code, which becomes \&\, resulting in cmd /c start 'http://domain.com?param1\&\param2'
// The start command uses ^ to escape special characters
func (i DefaultInteractor) BuildWindowsAgsAndURL(url string) (args []string, escapedURL string) {
	return []string{"/c", "start"},
		strings.ReplaceAll(strings.ReplaceAll(url, " ", "%20"), "&", `^&`)
}
