package runc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func NewCgManager(spec *specs.Spec, usedSystemdCgroup bool) (cgroups.Manager, *configs.Config, error) {
	config, err := createlibcontainerConfig(spec, usedSystemdCgroup)
	if err != nil {
		glog.Errorf("newCgManager get error: %v", err)
		return nil, nil, err
	}
	if usedSystemdCgroup {
		return &systemd.Manager{
			Cgroups: config.Cgroups,
			Paths:   nil,
		}, config, nil
	}
	return &fs.Manager{
		Cgroups: config.Cgroups,
		Paths:   nil,
	}, config, nil
}

func createlibcontainerConfig(spec *specs.Spec, usedSystemdCgroup bool) (*configs.Config, error) {
	config := &configs.Config{}

	c, err := createCgroupConfig(spec, usedSystemdCgroup)
	if err != nil {
		return nil, err
	}

	config.Cgroups = c

	return config, nil
}

func createCgroupConfig(spec *specs.Spec, usedSystemdCgroup bool) (*configs.Cgroup, error) {
	var myCgroupPath string

	c := &configs.Cgroup{
		Resources: &configs.Resources{},
	}

	if spec.Annotations != nil {
		if v, ok := spec.Annotations["__memory_wmark_ratio"]; ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				c.MemoryWmarkRatio = n
			}
		}

		if v, ok := spec.Annotations["__memory_extra_in_bytes"]; ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				c.MemoryExtraInBytes = n
			}
		}

		if v, ok := spec.Annotations["__memory_force_empty_ctl"]; ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				c.MemoryForceEmptyCtl = n
			}
		}
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

	if spec.Linux == nil {
		return c, nil
	}
	r := spec.Linux.Resources
	if r == nil {
		return c, nil
	}
	if r.Memory != nil {
		if r.Memory.Limit != nil {
			c.Resources.Memory = int64(*r.Memory.Limit)
		}
		if r.Memory.Reservation != nil {
			c.Resources.MemoryReservation = int64(*r.Memory.Reservation)
		}
		if r.Memory.Swap != nil {
			c.Resources.MemorySwap = int64(*r.Memory.Swap)
		}
		if r.Memory.Kernel != nil {
			c.Resources.KernelMemory = int64(*r.Memory.Kernel)
		}
		if r.Memory.KernelTCP != nil {
			c.Resources.KernelMemoryTCP = int64(*r.Memory.KernelTCP)
		}
		if r.Memory.Swappiness != nil {
			swappiness := int64(*r.Memory.Swappiness)
			c.Resources.MemorySwappiness = &swappiness
		}
	}
	if r.CPU != nil {
		if r.CPU.Shares != nil {
			c.Resources.CpuShares = int64(*r.CPU.Shares)
		}
		if r.CPU.Quota != nil {
			c.Resources.CpuQuota = int64(*r.CPU.Quota)
		}
		if r.CPU.Period != nil {
			c.Resources.CpuPeriod = int64(*r.CPU.Period)
		}
		if r.CPU.RealtimeRuntime != nil {
			c.Resources.CpuRtRuntime = int64(*r.CPU.RealtimeRuntime)
		}
		if r.CPU.RealtimePeriod != nil {
			c.Resources.CpuRtPeriod = int64(*r.CPU.RealtimePeriod)
		}
		if r.CPU.Cpus != nil {
			c.Resources.CpusetCpus = *r.CPU.Cpus
		}
		if r.CPU.Mems != nil {
			c.Resources.CpusetMems = *r.CPU.Mems
		}
		if spec.Annotations != nil {
			c.Resources.CpuBvtWarpNs, _ = strconv.ParseInt(spec.Annotations["__cput_bvt_warp_ns"], 10, 64)
		}
	}

	if spec.Annotations != nil {
		c.Resources.IntelRdtL3Cbm = spec.Annotations["__intel_rdt.l3_cbm"]
		c.Resources.BlkFileLevelSwitch, _ = strconv.Atoi(spec.Annotations["__BlkFileLevelSwitch"])
		c.Resources.BlkMetaWriteTps, _ = strconv.Atoi(spec.Annotations["__BlkMetaWriteTps"])
		c.Resources.BlkBufferWriteBps, _ = strconv.Atoi(spec.Annotations["__BlkBufferWriteBps"])
		c.Resources.BlkBufferWriteSwitch, _ = strconv.Atoi(spec.Annotations["__BlkBufferWriteSwitch"])
		paths := spec.Annotations["__BlkFileThrottlePath"]
		if len(paths) > 0 {
			c.Resources.BlkFileThrottlePath = strings.Split(paths, ",")
		}
	}

	if r.Pids != nil {
		c.Resources.PidsLimit = *r.Pids.Limit
	}
	if r.BlockIO != nil {
		if r.BlockIO.Weight != nil {
			c.Resources.BlkioWeight = *r.BlockIO.Weight
		}
		if r.BlockIO.LeafWeight != nil {
			c.Resources.BlkioLeafWeight = *r.BlockIO.LeafWeight
		}
		if r.BlockIO.WeightDevice != nil {
			for _, wd := range r.BlockIO.WeightDevice {
				var weight, leafWeight uint16
				if wd.Weight != nil {
					weight = *wd.Weight
				}
				if wd.LeafWeight != nil {
					leafWeight = *wd.LeafWeight
				}
				weightDevice := configs.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
				c.Resources.BlkioWeightDevice = append(c.Resources.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.ThrottleReadBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadBpsDevice = append(c.Resources.BlkioThrottleReadBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteBpsDevice = append(c.Resources.BlkioThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadIOPSDevice = append(c.Resources.BlkioThrottleReadIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteIOPSDevice = append(c.Resources.BlkioThrottleWriteIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleBufferWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleBufferWriteBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkBufferThrottleWriteBpsDevice = append(c.Resources.BlkBufferThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadLowBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadLowBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadLowBpsDevice = append(c.Resources.BlkioThrottleReadLowBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadLowIOpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadLowIOpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadLowIOpsDevice = append(c.Resources.BlkioThrottleReadLowIOpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteLowBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteLowBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteLowBpsDevice = append(c.Resources.BlkioThrottleWriteLowBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteLowIOpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteLowIOpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteLowIOpsDevice = append(c.Resources.BlkioThrottleWriteLowIOpsDevice, throttleDevice)
			}
		}
	}
	for _, l := range r.HugepageLimits {
		c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &configs.HugepageLimit{
			Pagesize: *l.Pagesize,
			Limit:    *l.Limit,
		})
	}
	if r.DisableOOMKiller != nil {
		c.Resources.OomKillDisable = *r.DisableOOMKiller
	}
	if r.Network != nil {
		if r.Network.ClassID != nil {
			c.Resources.NetClsClassid = *r.Network.ClassID
		}
		for _, m := range r.Network.Priorities {
			c.Resources.NetPrioIfpriomap = append(c.Resources.NetPrioIfpriomap, &configs.IfPrioMap{
				Interface: m.Name,
				Priority:  int64(m.Priority),
			})
		}
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
