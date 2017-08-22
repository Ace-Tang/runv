package cgroups

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
)

var (
	EnableKernelMem = true
)

// VersionInfo holds information about the kernel.
type VersionInfo struct {
	Kernel int    // Version of the kernel (e.g. 4.1.2-generic -> 4)
	Major  int    // Major part of the kernel version (e.g. 4.1.2-generic -> 1)
	Minor  int    // Minor part of the kernel version (e.g. 4.1.2-generic -> 2)
	Flavor string // Flavor of the kernel version (e.g. 4.1.2-generic -> generic)
}

func init() {
	if k, e := GetKernelVersion(); e == nil {
		EnableKernelMem = k.Kernel >= 4
	}
}

// ParseRelease parses a string and creates a VersionInfo based on it.
func ParseRelease(release string) (*VersionInfo, error) {
	var (
		kernel, major, minor, parsed int
		flavor, partial              string
	)

	// Ignore error from Sscanf to allow an empty flavor.  Instead, just
	// make sure we got all the version numbers.
	parsed, _ = fmt.Sscanf(release, "%d.%d%s", &kernel, &major, &partial)
	if parsed < 2 {
		return nil, errors.New("Can't parse kernel version " + release)
	}

	// sometimes we have 3.12.25-gentoo, but sometimes we just have 3.12-1-amd64
	parsed, _ = fmt.Sscanf(partial, ".%d%s", &minor, &flavor)
	if parsed < 1 {
		flavor = partial
	}

	return &VersionInfo{
		Kernel: kernel,
		Major:  major,
		Minor:  minor,
		Flavor: flavor,
	}, nil
}

// GetKernelVersion gets the current kernel version.
func GetKernelVersion() (*VersionInfo, error) {
	uts, err := uname()
	if err != nil {
		return nil, err
	}

	release := make([]byte, len(uts.Release))

	i := 0
	for _, c := range uts.Release {
		release[i] = byte(c)
		i++
	}

	// Remove the \x00 from the release for Atoi to parse correctly
	release = release[:bytes.IndexByte(release, 0)]

	return ParseRelease(string(release))
}

func uname() (*syscall.Utsname, error) {
	uts := &syscall.Utsname{}

	if err := syscall.Uname(uts); err != nil {
		return nil, err
	}
	return uts, nil
}
