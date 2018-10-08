package os

import (
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
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
