package runc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func NewCgManager(spec *specs.Spec, usedSystemdCgroup bool) (cgroups.Manager, error) {
	cgConfig, err := createCgroupConfig(spec, usedSystemdCgroup)
	if err != nil {
		glog.Errorf("newCgManager get error: %v", err)
		return nil, err
	}
	if usedSystemdCgroup {
		return &systemd.Manager{
			Cgroups: cgConfig,
			Paths:   nil,
		}, nil
	}
	return &fs.Manager{
		Cgroups: cgConfig,
		Paths:   nil,
	}, nil
}

func createCgroupConfig(spec *specs.Spec, usedSystemdCgroup bool) (*configs.Cgroup, error) {
	var myCgroupPath string

	c := &configs.Cgroup{
		Resources: &configs.Resources{},
	}

	if spec.Linux != nil && spec.Linux.CgroupsPath != nil {
		myCgroupPath = cleanPath(*spec.Linux.CgroupsPath)
		if usedSystemdCgroup {
			myCgroupPath = *spec.Linux.CgroupsPath
		}
	}

	glog.Infof("cgroup path %v", myCgroupPath)
	glog.Infof("CgManager driver is systemd: %v", usedSystemdCgroup)
	if usedSystemdCgroup {
		if !systemd.UseSystemd() {
			return nil, fmt.Errorf("systemd cgroup flag passed, but systemd support for managing cgroups is not available")
		}
		if myCgroupPath == "" {
			c.Parent = "system.slice"
			c.ScopePrefix = "runv"
			//		c.Name = name
		} else {
			// Parse the path from expected "slice:prefix:name"
			// for e.g. "system.slice:docker:1234"
			parts := strings.Split(myCgroupPath, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("expected cgroupsPath to be of format \"slice:prefix:name\" for systemd cgroups")
			}
			c.Parent = parts[0]
			c.ScopePrefix = parts[1]
			c.Name = parts[2]
		}
	} else {
		/*
			if myCgroupPath == "" {
				c.Name = name
			}
		*/
		c.Path = myCgroupPath
	}

	return c, nil
}

func cleanPath(path string) string {
	// Deal with empty strings nicely.
	if path == "" {
		return ""
	}

	// Ensure that all paths are cleaned (especially problematic ones like
	// "/../../../../../" which can cause lots of issues).
	path = filepath.Clean(path)

	// If the path isn't absolute, we need to do more processing to fix paths
	// such as "../../../../<etc>/some/path". We also shouldn't convert absolute
	// paths to relative ones.
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		// This can't fail, as (by definition) all paths are relative to root.
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}

	// Clean the path again for good measure.
	return filepath.Clean(path)
}
