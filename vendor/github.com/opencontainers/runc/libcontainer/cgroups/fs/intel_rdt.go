// +build linux

package fs

import (
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type IntelRdtGroup struct {
}

func (s *IntelRdtGroup) Name() string {
	return "intel_rdt"
}

func (s *IntelRdtGroup) Apply(d *cgroupData) error {
	path, err := d.path("intel_rdt")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}
	return s.ApplyDir(path, d.config, d.pid)
}

func (s *IntelRdtGroup) ApplyDir(path string, cgroup *configs.Cgroup, pid int) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}

	// because we are not using d.join we need to place the pid into the procs file
	// unlike the other subsystems
	if err := cgroups.WriteCgroupProc(path, pid, cgroup); err != nil {
		return err
	}

	return nil
}

func (s *IntelRdtGroup) Set(path string, cgroup *configs.Cgroup) error {
	if path != "" && cgroup.Resources.IntelRdtL3Cbm != "" {
		if err := writeFileIfExist(path, "intel_rdt.l3_cbm", cgroup.Resources.IntelRdtL3Cbm); err != nil {
			return err
		}
	}

	return nil
}

func (s *IntelRdtGroup) Remove(d *cgroupData) error {
	return removePath(d.path(s.Name()))
}

// Returns the stats, as 'stats', corresponding to the cgroup under 'path'.
func (s *IntelRdtGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}
