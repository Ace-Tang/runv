package supervisor

import (
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/hyperhq/runv/api"
	"github.com/hyperhq/runv/factory"
	"github.com/hyperhq/runv/hypervisor"
	"github.com/kardianos/osext"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetlinkUpdateType string

const (
	UpdateTypeLink  NetlinkUpdateType = "link"
	UpdateTypeAddr  NetlinkUpdateType = "addr"
	UpdateTypeRoute NetlinkUpdateType = "route"
)

// NetlinkUpdate tracks the change of network namespace.
type NetlinkUpdate struct {
	// AddrUpdate is used to pass information back from AddrSubscribe()
	Addr netlink.AddrUpdate
	// RouteUpdate is used to pass information back from RouteSubscribe()
	Route netlink.RouteUpdate
	// Veth is used to pass information back from LinkSubscribe().
	// We only support veth link at present.
	Veth *netlink.Veth

	// UpdateType indicates which part of the netlink information has been changed.
	UpdateType NetlinkUpdateType
}

type HyperPod struct {
	Containers map[string]*Container
	Processes  map[string]*Process

	//userPod   *pod.UserPod
	//podStatus *hypervisor.PodStatus
	vm *hypervisor.Vm
	sv *Supervisor

	nslistener *nsListener
}

type InterfaceInfo struct {
	Index     int
	PeerIndex int
	Ip        string
}

type nsListener struct {
	enc *gob.Encoder
	dec *gob.Decoder
	cmd *exec.Cmd
}

func GetBridgeFromIndex(idx int) (string, string, error) {
	var attr, bridge *netlink.LinkAttrs
	var options string

	links, err := netlink.LinkList()
	if err != nil {
		glog.Error(err)
		return "", "", err
	}

	for _, link := range links {
		if link.Type() != "veth" {
			continue
		}

		if link.Attrs().Index == idx {
			attr = link.Attrs()
			break
		}
	}

	if attr == nil {
		return "", "", fmt.Errorf("cann't find nic whose ifindex is %d", idx)
	}

	for _, link := range links {
		if link.Type() != "bridge" && link.Type() != "openvswitch" {
			continue
		}

		if link.Attrs().Index == attr.MasterIndex {
			bridge = link.Attrs()
			break
		}
	}

	if bridge == nil {
		return "", "", fmt.Errorf("cann't find bridge contains nic whose ifindex is %d", idx)
	}

	if bridge.Name == "ovs-system" {
		veth, err := netlink.LinkByIndex(idx)
		if err != nil {
			return "", "", err
		}

		out, err := exec.Command("ovs-vsctl", "port-to-br", veth.Attrs().Name).CombinedOutput()
		if err != nil {
			return "", "", err
		}
		bridge.Name = strings.TrimSpace(string(out))

		out, err = exec.Command("ovs-vsctl", "get", "port", veth.Attrs().Name, "tag").CombinedOutput()
		if err != nil {
			return "", "", err
		}
		options = "tag=" + strings.TrimSpace(string(out))
	}

	glog.V(3).Infof("find bridge %s", bridge.Name)

	return bridge.Name, options, nil
}

func (hp *HyperPod) initPodNetwork(c *Container) error {
	// Only start first container will setup netns
	if len(hp.Containers) > 1 {
		return nil
	}

	// container has no prestart hooks, means no net for this container
	if c.Spec.Hooks == nil || len(c.Spec.Hooks.Prestart) == 0 {
		// FIXME: need receive interface settting?
		return nil
	}

	listener := hp.nslistener

	/* send collect netns request to nsListener */
	if err := listener.enc.Encode("init"); err != nil {
		glog.Errorf("listener.dec.Decode init error: %v", err)
		return err
	}

	infos := []InterfaceInfo{}
	/* read nic information of ns from pipe */
	err := listener.dec.Decode(&infos)
	if err != nil {
		glog.Error("listener.dec.Decode infos error: %v", err)
		return err
	}

	routes := []netlink.Route{}
	err = listener.dec.Decode(&routes)
	if err != nil {
		glog.Error("listener.dec.Decode route error: %v", err)
		return err
	}

	var gw_route *netlink.Route
	for idx, route := range routes {
		if route.Dst == nil {
			gw_route = &routes[idx]
		}
	}

	glog.V(3).Infof("interface configuration of pod ns is %#v", infos)
	for _, info := range infos {
		bridge, options, err := GetBridgeFromIndex(info.PeerIndex)
		if err != nil {
			glog.Error(err)
			continue
		}

		nicId := strconv.Itoa(info.Index)

		conf := &api.InterfaceDescription{
			Id:      nicId, //ip as an id
			Lo:      false,
			Bridge:  bridge,
			Ip:      info.Ip,
			Options: options,
		}

		if gw_route != nil && gw_route.LinkIndex == info.Index {
			conf.Gw = gw_route.Gw.String()
		}

		// TODO(hukeping): the name here is always eth1, 2, 3, 4, 5, etc.,
		// which would not be the proper way to name device name, instead it
		// should be the same as what we specified in the network namespace.
		//err = hp.vm.AddNic(info.Index, fmt.Sprintf("eth%d", idx), conf)
		err = hp.vm.AddNic(conf)
		if err != nil {
			glog.Error(err)
			return err
		}
	}

	err = hp.vm.AddRoute()
	if err != nil {
		glog.Error(err)
		return err
	}

	go hp.nsListenerStrap()

	return nil
}

func (hp *HyperPod) nsListenerStrap() {
	listener := hp.nslistener

	// Keep watching container network setting
	// and then update vm/hyperstart
	for {
		update := NetlinkUpdate{}
		err := listener.dec.Decode(&update)
		if err != nil {
			if err == io.EOF {
				glog.V(3).Infof("listener.dec.Decode NetlinkUpdate: %v", err)
				break
			}
			glog.Error("listener.dec.Decode NetlinkUpdate error: %v", err)
			continue
		}

		glog.V(3).Infof("network namespace information of %s has been changed", update.UpdateType)
		switch update.UpdateType {
		case UpdateTypeLink:
			link := update.Veth
			if link.Attrs().ParentIndex == 0 {
				glog.V(3).Infof("The deleted link: %s", link)
				err = hp.vm.DeleteNic(strconv.Itoa(link.Attrs().Index))
				if err != nil {
					glog.Error(err)
					continue
				}

			} else {
				glog.V(3).Infof("The changed link: %s", link)
			}

		case UpdateTypeAddr:
			glog.V(3).Infof("The changed address: %s", update.Addr)

			link := update.Veth

			// If there is a delete operation upon an link, it will also trigger
			// the address change event which the link will be NIL since it has
			// already been deleted before the address change event be triggered.
			if link == nil {
				glog.V(3).Info("Link for this address has already been deleted.")
				continue
			}

			// This is just a sanity check.
			//
			// The link should be the one which the address on it has been changed.
			if link.Attrs().Index != update.Addr.LinkIndex {
				glog.Errorf("Get the wrong link with ID %d, expect %d", link.Attrs().Index, update.Addr.LinkIndex)
				continue
			}

			bridge, options, err := GetBridgeFromIndex(link.Attrs().ParentIndex)
			if err != nil {
				glog.Error(err)
				continue
			}

			inf := &api.InterfaceDescription{
				Id:      strconv.Itoa(link.Attrs().Index),
				Lo:      false,
				Bridge:  bridge,
				Ip:      update.Addr.LinkAddress.String(),
				Options: options,
			}

			err = hp.vm.AddNic(inf)
			if err != nil {
				glog.Error(err)
				continue
			}

		case UpdateTypeRoute:

		}
	}
}

func newPipe() (parent, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func (hp *HyperPod) startNsListener() (err error) {
	var parentPipe, childPipe *os.File
	var path string
	if hp.nslistener != nil {
		return nil
	}

	path, err = osext.Executable()
	if err != nil {
		glog.Errorf("cannot find self executable path for %s: %v", os.Args[0], err)
		return err
	}

	glog.V(3).Infof("get exec path %s", path)
	parentPipe, childPipe, err = newPipe()
	if err != nil {
		glog.Errorf("create pipe for containerd-nslistener failed: %v", err)
		return err
	}

	defer func() {
		if err != nil {
			parentPipe.Close()
			childPipe.Close()
		}
	}()

	cmd := exec.Command(path)
	cmd.Args[0] = "containerd-nslistener"
	cmd.ExtraFiles = append(cmd.ExtraFiles, childPipe)
	if err = cmd.Start(); err != nil {
		glog.Errorf("start containerd-nslistener failed: %v", err)
		return err
	}

	childPipe.Close()

	enc := gob.NewEncoder(parentPipe)
	dec := gob.NewDecoder(parentPipe)

	hp.nslistener = &nsListener{
		enc: enc,
		dec: dec,
		cmd: cmd,
	}

	defer func() {
		if err != nil {
			hp.stopNsListener()
		}
	}()

	/* Make sure nsListener create new netns */
	var ready string
	if err = dec.Decode(&ready); err != nil {
		glog.Errorf("Get ready message from containerd-nslistener failed: %v", err)
		return err
	}

	if ready != "init" {
		err = fmt.Errorf("containerd get incorrect init message: %s", ready)
		return err
	}

	glog.V(1).Infof("nsListener pid is %d", hp.getNsPid())
	return nil
}

func (hp *HyperPod) stopNsListener() {
	if hp.nslistener != nil {
		hp.nslistener.cmd.Process.Kill()
	}
}

func (hp *HyperPod) getNsPid() int {
	if hp.nslistener == nil {
		return -1
	}

	procPath, ex := ioutil.TempDir("", "runv-containerd")
	if ex != nil {
		glog.Errorf("error create temp dir %v", ex)
		return hp.nslistener.cmd.Process.Pid
	}

	defer os.RemoveAll(procPath)

	if e := unix.Mount("proc", procPath,
		"proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); e != nil {
		glog.Errorf("mount %s error %v", procPath, e)
	} else {
		defer unix.Unmount(procPath, unix.MNT_DETACH)
	}

	pid := hp.nslistener.cmd.Process.Pid
	ba, e := ioutil.ReadFile(fmt.Sprintf("%s/%d/sched", procPath, pid))
	if e != nil {
		glog.Errorf("read file error. %s %v", fmt.Sprintf("/proc/%d/sched", e))
		return pid
	}
	s := string(ba)
	start := strings.Index(s, "(")
	end := strings.Index(s[start:], ",")
	if start > 0 && end > 0 {
		end = start + end
		if newPid, ex := strconv.Atoi(s[start+1 : end]); ex == nil {
			return newPid
		} else {
			glog.Errorf("parse pid error %s %v %s", s[start+1:end], ex, s)
		}
	}
	return pid
}

func (hp *HyperPod) createContainer(container, bundlePath, stdin, stdout, stderr string, spec *specs.Spec, usedSystemdCgroup bool) (*Container, error) {
	inerProcessId := container + "-init"
	if _, ok := hp.Processes[inerProcessId]; ok {
		return nil, fmt.Errorf("The process id: %s is in used", inerProcessId)
	}

	c := &Container{
		Id:         container,
		BundlePath: bundlePath,
		Spec:       spec,
		Processes:  make(map[string]*Process),
		ownerPod:   hp,
	}
	if manager, err := newCgManager(spec, usedSystemdCgroup); err == nil {
		c.CgManager = manager
		glog.Infof("CgManager driver is systemd: %v", usedSystemdCgroup)
	}

	hp.Containers[container] = c
	p := &Process{
		Id:     "init",
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Spec:   &spec.Process,
		ProcId: c.ownerPod.getNsPid(),

		inerId:    inerProcessId,
		ownerCont: c,
		init:      true,
	}
	c.Processes["init"] = p
	hp.Processes[inerProcessId] = p
	return c, nil
}

func chooseKernel(spec *specs.Spec) (kernel string) {
	for k, env := range spec.Process.Env {
		slices := strings.Split(env, "=")
		if len(slices) == 2 && slices[0] == "hypervisor.kernel" {
			kernel = slices[1]
			// remove kernel env because this is only allow to be used by runv
			spec.Process.Env = append(spec.Process.Env[:k], spec.Process.Env[k+1:]...)
			break
		}
	}
	return
}

func chooseInitrd(spec *specs.Spec) (initrd string) {
	for k, env := range spec.Process.Env {
		slices := strings.Split(env, "=")
		if len(slices) == 2 && slices[0] == "hypervisor.initrd" {
			initrd = slices[1]
			// remove kernel env because this is only allow to be used by runv
			spec.Process.Env = append(spec.Process.Env[:k], spec.Process.Env[k+1:]...)
			break
		}
	}
	return
}

func createHyperPod(f factory.Factory, spec *specs.Spec, defaultCpus int, defaultMemory int) (*HyperPod, error) {
	cpu := defaultCpus
	mem := defaultMemory
	if spec.Linux != nil && spec.Linux.Resources != nil && spec.Linux.Resources.Memory != nil && spec.Linux.Resources.Memory.Limit != nil {
		mem = int(*spec.Linux.Resources.Memory.Limit >> 20)
	}

	kernel := chooseKernel(spec)
	initrd := chooseInitrd(spec)
	glog.V(3).Infof("Using kernel: %s; Initrd: %s; vCPU: %d; Memory %d", kernel, initrd, cpu, mem)

	var (
		vm  *hypervisor.Vm
		err error
	)
	if len(kernel) == 0 && len(initrd) == 0 {
		vm, err = f.GetVm(cpu, mem)
		if err != nil {
			glog.Errorf("Create VM failed with default kernel config: %v", err)
			return nil, err
		}
		glog.V(3).Infof("Creating VM with default kernel config")
	} else if len(kernel) == 0 || len(initrd) == 0 {
		// if user specify a kernel, they must specify an initrd at the same time
		return nil, fmt.Errorf("You must specify an initrd if you specify a kernel, or vice-versa")
	} else {
		boot := &hypervisor.BootConfig{
			CPU:    cpu,
			Memory: mem,
			Kernel: kernel,
			Initrd: initrd,
		}

		vm, err = hypervisor.GetVm("", boot, true)
		if err != nil {
			glog.Errorf("Create VM failed: %v", err)
			return nil, err
		}
		glog.V(3).Infof("Creating VM with specific kernel config")
	}

	r := make(chan api.Result, 1)
	go func() {
		r <- vm.WaitInit()
	}()

	sandbox := api.SandboxInfoFromOCF(spec)
	vm.InitSandbox(sandbox)

	rsp := <-r

	if !rsp.IsSuccess() {
		vm.Kill()
		glog.Errorf("StartPod fail, response: %#v", rsp)
		return nil, fmt.Errorf("StartPod fail")
	}
	glog.V(3).Infof("%s init sandbox successfully", rsp.ResultId())

	hp := &HyperPod{
		vm:         vm,
		Containers: make(map[string]*Container),
		Processes:  make(map[string]*Process),
	}

	// create Listener process running in its own netns
	if err = hp.startNsListener(); err != nil {
		hp.reap()
		glog.Errorf("start ns listener fail: %v", err)
		return nil, err
	}

	return hp, nil
}

func (hp *HyperPod) reap() {
	result := make(chan api.Result, 1)
	go func() {
		result <- hp.vm.Shutdown()
	}()
	select {
	case rsp, ok := <-result:
		if !ok || !rsp.IsSuccess() {
			glog.Errorf("StopPod fail: chan: %v, response: %v", ok, rsp)
			break
		}
		glog.V(1).Infof("StopPod successfully")
	case <-time.After(time.Second * 60):
		glog.Errorf("StopPod timeout")
	}

	hp.stopNsListener()
	if err := os.RemoveAll(filepath.Join(hypervisor.BaseDir, hp.vm.Id)); err != nil {
		glog.Errorf("can't remove vm dir %q: %v", filepath.Join(hypervisor.BaseDir, hp.vm.Id), err)
	}
	glog.Flush()
}

func newCgManager(spec *specs.Spec, usedSystemdCgroup bool) (cgroups.Manager, error) {
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

	if usedSystemdCgroup {
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
			glog.Infof("cgroup path %+v", parts)
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
