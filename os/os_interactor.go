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
		args = []string{"/c", "start"}
		// The character & is treated as running a separate command in Windows
		// cmd /c start "http://domain.com?param1&param2" results in trying to run cmd /c "start http://domain.com?parm1" & param2
		// Also, the " char is used as the delimiter to escape special characters, so "&" would become \&\
		// cmd /c start 'http://domain.com?param1=value with space"&"param2=value2' works when inputting directly to the command prompt,
		// but the "&" is escaped by \"&\" when passed from code, which becomes \&\, resulting in cmd /c start 'http://domain.com?param1\&\param2'
		// The start command uses ^ to escape special characters
		url = strings.ReplaceAll(strings.ReplaceAll(url, " ", "%20"), "&", `^&`)
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
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
