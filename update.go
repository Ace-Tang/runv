package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	runcutils "github.com/opencontainers/runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

var updateCommand = cli.Command{
	Name:      "update",
	Usage:     "update container resource constraints",
	ArgsUsage: `<container-id>`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "resources, r",
			Value: "",
			Usage: `path to the file containing the resources to update or '-' to read from the standard input
 
 The accepted format is as follow (unchanged values can be omitted):
 
 {
   "memory": {
     "limit": 0,
     "reservation": 0,
     "swap": 0,
     "kernel": 0,
     "kernelTCP": 0
   },
   "cpu": {
     "shares": 0,
     "quota": 0,
     "period": 0,
     "cpus": "",
     "mems": ""
   },
   "blockIO": {
     "blkioWeight": 0
   },
 }
 
 Note: if data is to be read from a file or the standard input, all
 other options are ignored.
 `,
		},
		cli.StringFlag{
			Name:  "cpuset-cpus",
			Usage: "cpus to use",
		},
		cli.StringFlag{
			Name:  "memory",
			Usage: "Memory limit (in bytes)",
		},
	},
	Action: updateContainer,
}

func u64Ptr(i int) *uint64 { ui := uint64(i); return &ui }

func updateContainer(context *cli.Context) error {
	container := context.Args().First()
	root := context.GlobalString("root")
	cpus := context.String("cpuset-cpus")
	memory := context.Int("memory")

	bundle, err := getBundle(root, container)
	if err != nil {
		return fmt.Errorf("get %s bundle error %s", container, err)
	}
	spec, err := loadSpec(filepath.Join(bundle, specConfig))
	if err != nil || spec == nil {
		return fmt.Errorf("get container %s spec error %s, or spec = nil", container, err)
	}

	if cpus != "" {
		linuxCpu := spec.Linux.Resources.CPU
		if linuxCpu != nil {
			linuxCpu.Cpus = &cpus
		} else {
			linuxCpu = &specs.LinuxCPU{
				Cpus: &cpus,
			}
		}
	}

	if memory != 0 {
		linuxMemory := spec.Linux.Resources.Memory
		if linuxMemory != nil {
			linuxMemory.Limit = u64Ptr(memory)
		} else {
			linuxMemory = &specs.LinuxMemory{
				Limit: u64Ptr(memory),
			}
		}
	}

	cgroupMg, config, err := runcutils.NewCgManager(spec, context.GlobalBool("systemd-cgroup"))
	if err != nil {
		logrus.Errorf("create cgroup manager error %v", err)
		return fmt.Errorf("create cgroup manager error %s", err)
	}

	err = cgroupMg.Set(config)
	if err != nil {
		logrus.Errorf("set config for cgroup error %v", err)
	}

	return nil
}

func getBundle(root, container string) (string, error) {
	statePath := filepath.Join(root, container, stateJson)
	if _, err := os.Stat(statePath); err != nil {
		return "", err
	}
	f, err := os.Open(statePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	state := &cState{}
	err = json.NewDecoder(f).Decode(state)
	if err != nil {
		return "", err
	}

	if state.Bundle == "" {
		return "", fmt.Errorf("bundle path is nil")
	}

	return state.Bundle, nil
}
