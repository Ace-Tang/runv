// +build linux,amd64

package qemu

import (
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/hyperhq/runv/hypervisor"
)

var (
	QemuVersion = "vlinux"
)

const (
	QEMU_SYSTEM_EXE = "qemu-system-x86_64"
	QEMU_LITE_EXE   = "/opt/vlinux/latest/qemu-lite/bin/qemu-system-x86_64"
)

func (qc *QemuContext) arguments(ctx *hypervisor.VmContext) []string {
	if ctx.Boot == nil {
		ctx.Boot = &hypervisor.BootConfig{
			CPU:    1,
			Memory: 128,
			Kernel: hypervisor.DefaultKernel,
			Initrd: hypervisor.DefaultInitrd,
		}
	}
	boot := ctx.Boot
	qc.cpus = boot.CPU

	var machineClass, memParams, cpuParams string
	machineClass = "pc-i440fx-2.1"
	memParams = fmt.Sprintf("size=%d,slots=1,maxmem=%dM", boot.Memory, hypervisor.DefaultMaxMem) // TODO set maxmem to the total memory of the system
	cpuParams = fmt.Sprintf("cpus=%d,maxcpus=%d", boot.CPU, hypervisor.DefaultMaxCpus)           // TODO set it to the cpus of the system

	cmdline := "console=ttyS0 panic=1 no_timer_check"
	params := []string{
		"-machine", machineClass + ",accel=kvm,usb=off", "-global", "kvm-pit.lost_tick_policy=discard", "-cpu", "host"}

	if QemuVersion == "vlinux" {
		machineClass = "pc-lite"
		cmdline = "root=/dev/pmem0p1 rootflags=dax,data=ordered,errors=remount-ro rw rootfstype=ext4 tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k panic=1 console=hvc0 console=hvc1 console=hvc2 console=hvc3 initcall_debug init=/usr/lib/systemd/systemd systemd.unit=cc-agent.target iommu=off quiet systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket systemd.show_status=false cryptomgr.notests"
		params = []string{
			"-machine", machineClass + ",accel=kvm,kernel_irqchip,nvdimm", "-device", "nvdimm,memdev=mem0,id=nv0",
			"-object", fmt.Sprintf("memory-backend-file,id=mem0,mem-path=%s,size=235929600", boot.MemoryPath),
			"-global", "kvm-pit.lost_tick_policy=discard", "-cpu", "host"}
	}
	if _, err := os.Stat("/dev/kvm"); os.IsNotExist(err) {
		glog.V(1).Info("kvm not exist change to no kvm mode")
		params = []string{"-machine", machineClass + ",usb=off", "-cpu", "core2duo"}
		cmdline += " clocksource=acpi_pm notsc"
	}

	if boot.Bios != "" && boot.Cbfs != "" {
		params = append(params,
			"-drive", fmt.Sprintf("if=pflash,file=%s,readonly=on", boot.Bios),
			"-drive", fmt.Sprintf("if=pflash,file=%s,readonly=on", boot.Cbfs))
	} else if boot.Bios != "" {
		params = append(params,
			"-bios", boot.Bios,
			"-kernel", boot.Kernel, "-initrd", boot.Initrd, "-append", cmdline)
	} else if boot.Cbfs != "" {
		params = append(params,
			"-drive", fmt.Sprintf("if=pflash,file=%s,readonly=on", boot.Cbfs))
	} else {
		params = append(params,
			"-kernel", boot.Kernel, "-append", cmdline)
		if QemuVersion != "vlinux" {
			params = append(params, "-initrd", boot.Initrd)
		}
	}

	params = append(params,
		"-realtime", "mlock=off", "-no-user-config", "-nodefaults", "-no-hpet",
		"-rtc", "base=utc,clock=vm,driftfix=slew", "-no-reboot", "-display", "none", "-boot", "strict=on",
		"-m", memParams, "-smp", cpuParams)

	if boot.BootToBeTemplate || boot.BootFromTemplate {
		memObject := fmt.Sprintf("memory-backend-file,id=hyper-template-memory,size=%dM,mem-path=%s", boot.Memory, boot.MemoryPath)
		if boot.BootToBeTemplate {
			memObject = memObject + ",share=on"
		}
		nodeConfig := fmt.Sprintf("node,nodeid=0,cpus=0-%d,memdev=hyper-template-memory", hypervisor.DefaultMaxCpus-1)
		params = append(params, "-object", memObject, "-numa", nodeConfig)
		if boot.BootFromTemplate {
			params = append(params, "-S", "-incoming", fmt.Sprintf("exec:cat %s", boot.DevicesStatePath))
		}
	} else {
		nodeConfig := fmt.Sprintf("node,nodeid=0,cpus=0-%d,mem=%d", hypervisor.DefaultMaxCpus-1, boot.Memory)
		params = append(params, "-numa", nodeConfig)
	}

	if QemuVersion == "vlinux" {
		params = append(params, "-qmp", fmt.Sprintf("unix:%s,server,nowait", qc.qmpSockName),
			"-device", "virtio-serial-pci,id=virtio-serial0", "-device", "virtio-scsi-pci,id=scsi0",

			"-device", "virtconsole,chardev=charconsole0,id=console0",
			"-chardev", fmt.Sprintf("socket,id=charconsole0,path=%s,server,nowait", ctx.ConsoleSockName),
			// hyperstart channel
			"-chardev", fmt.Sprintf("socket,id=charch1,path=%s,server,nowait", ctx.TtySockName),
			"-device", "virtserialport,bus=virtio-serial0.0,nr=2,chardev=charch1,id=channel1,name=sh.hyper.channel.1",
			"-chardev", fmt.Sprintf("socket,id=charch0,path=%s,server,nowait", ctx.HyperSockName),
			"-device", "virtserialport,bus=virtio-serial0.0,nr=1,chardev=charch0,id=channel0,name=sh.hyper.channel.0",

			"-fsdev", fmt.Sprintf("local,id=virtio9p,path=%s,security_model=none", ctx.ShareDir),
			"-device", fmt.Sprintf("virtio-9p-pci,fsdev=virtio9p,mount_tag=%s", hypervisor.ShareDirTag),
		)

		if qc.debug {
			// reserved for debugging qemu console
			params = append(params, "-device", "virtconsole,chardev=charconsole1,id=console1",
				"-chardev", fmt.Sprintf("socket,id=charconsole1,path=%s,server,nowait", fmt.Sprintf("%s.debug", ctx.ConsoleSockName)))
		}

	} else {

		params = append(params, "-qmp", fmt.Sprintf("unix:%s,server,nowait", qc.qmpSockName), "-serial", fmt.Sprintf("unix:%s,server,nowait", ctx.ConsoleSockName),
			"-device", "virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x2", "-device", "virtio-scsi-pci,id=scsi0,bus=pci.0,addr=0x3",
			"-chardev", fmt.Sprintf("socket,id=charch0,path=%s,server,nowait", ctx.HyperSockName),
			"-device", "virtserialport,bus=virtio-serial0.0,nr=1,chardev=charch0,id=channel0,name=sh.hyper.channel.0",
			"-chardev", fmt.Sprintf("socket,id=charch1,path=%s,server,nowait", ctx.TtySockName),
			"-device", "virtserialport,bus=virtio-serial0.0,nr=2,chardev=charch1,id=channel1,name=sh.hyper.channel.1",
			"-fsdev", fmt.Sprintf("local,id=virtio9p,path=%s,security_model=none", ctx.ShareDir),
			"-device", fmt.Sprintf("virtio-9p-pci,fsdev=virtio9p,mount_tag=%s", hypervisor.ShareDirTag),
		)
	}
	if qc.driver.debug {
		glog.Infof("qemu will run in debug mode")
	}

	return params
}
