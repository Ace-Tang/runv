package supervisor

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/golang/glog"
	"github.com/hyperhq/runv/factory"
	runcutils "github.com/opencontainers/runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type Supervisor struct {
	StateDir string
	Factory  factory.Factory
	// Default CPU and memory amounts to use when not specified by container
	defaultCpus   int
	defaultMemory int

	Events SvEvents

	sync.RWMutex // Protects Supervisor.Containers, HyperPod.Containers, HyperPod.Processes, Container.Processes
	Containers   map[string]*Container

	UsedSystemdCgroup bool
	CtrdPid           int
}

func New(stateDir, eventLogDir string, f factory.Factory, defaultCpus int, defaultMemory int, usedSystemdCgroup bool, pid int) (*Supervisor, error) {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(eventLogDir, 0755); err != nil {
		return nil, err
	}
	if defaultCpus <= 0 {
		return nil, fmt.Errorf("defaultCpu must be greater than 0.")
	}
	if defaultMemory <= 0 {
		return nil, fmt.Errorf("defaultMemory must be greater than 0.")
	}
	sv := &Supervisor{
		StateDir:          stateDir,
		Factory:           f,
		defaultCpus:       defaultCpus,
		defaultMemory:     defaultMemory,
		Containers:        make(map[string]*Container),
		UsedSystemdCgroup: usedSystemdCgroup,
		CtrdPid:           pid,
	}
	sv.Events.subscribers = make(map[chan Event]struct{})
	go sv.reaper()
	return sv, sv.Events.setupEventLog(eventLogDir)
}

func (sv *Supervisor) CreateContainer(container, bundlePath, stdin, stdout, stderr string, spec *specs.Spec) (c *Container, err error) {
	defer func() {
		if err == nil {
			err = c.create()
		}
		if err != nil {
			sv.reap(container, "init")
		}
	}()
	sv.Lock()
	defer sv.Unlock()

	hp, err := sv.getHyperPod(container, spec)
	if err != nil {
		return nil, err
	}
	c, err = hp.createContainer(container, bundlePath, stdin, stdout, stderr, spec)
	if err != nil {
		return nil, err
	}
	sv.Containers[container] = c
	glog.V(1).Infof("supervisor creates container %q successfully", container)
	return c, nil
}

func (sv *Supervisor) StartContainer(container string, spec *specs.Spec) (c *Container, p *Process, err error) {
	defer func() {
		glog.V(3).Infof("Supervisor.StartContainer() return: c: %#v p: %#v", c, p)
		if err == nil {
			err = c.start(p)
		}
		if err != nil {
			glog.Errorf("Supervisor.StartContainer() failed: %#v", err)
			sv.reap(container, "init")
		}
	}()
	sv.Lock()
	defer sv.Unlock()
	if c, ok := sv.Containers[container]; ok {
		return c, c.Processes["init"], nil
	}
	return nil, nil, fmt.Errorf("container %s is not found for StartContainer()", container)
}

func (sv *Supervisor) AddProcess(container, processId, stdin, stdout, stderr string, spec *specs.Process) (*Process, error) {
	sv.Lock()
	defer sv.Unlock()
	if c, ok := sv.Containers[container]; ok {
		return c.addProcess(processId, stdin, stdout, stderr, spec)
	}
	return nil, fmt.Errorf("container %s is not found for AddProcess()", container)
}

func (sv *Supervisor) TtyResize(container, processId string, width, height int) error {
	sv.RLock()
	defer sv.RUnlock()
	p := sv.getProcess(container, processId)
	if p != nil {
		return p.ttyResize(container, width, height)
	}
	return fmt.Errorf("The container %s or the process %s is not found", container, processId)
}

func (sv *Supervisor) CloseStdin(container, processId string) error {
	sv.RLock()
	defer sv.RUnlock()
	p := sv.getProcess(container, processId)
	if p != nil {
		return p.closeStdin()
	}
	return fmt.Errorf("The container %s or the process %s is not found", container, processId)
}

func (sv *Supervisor) Signal(container, processId string, sig int) error {
	sv.RLock()
	defer sv.RUnlock()
	p := sv.getProcess(container, processId)
	if p != nil {
		return p.signal(sig)
	}
	return fmt.Errorf("The container %s or the process %s is not found", container, processId)
}

func (sv *Supervisor) getProcess(container, processId string) *Process {
	if c, ok := sv.Containers[container]; ok {
		if p, ok := c.Processes[processId]; ok {
			return p
		}
	}
	return nil
}

func (sv *Supervisor) reaper() {
	// start handling signals as soon as possible so that things are properly reaped
	// or if runtime exits before we hit the handler
	signals := make(chan os.Signal, 2048)
	signal.Notify(signals)

	events := sv.Events.Events(time.Time{})
	select {
	case e := <-events:
		if e.Type == EventExit {
			logrus.Infof("process exit %s %s", e.ID, e.PID)
			go sv.reap(e.ID, e.PID)
		}
	case s := <-signals:
		if s == syscall.SIGCHLD {
			exits, _ := Reap(false)
			for _, e := range exits {
				logrus.Infof("runv-containerd: get pid exit %d", e.Pid)
			}
		}
	}
}

func (sv *Supervisor) reap(container, processId string) {
	glog.Infof("reap container %s processId %s", container, processId)
	sv.Lock()
	defer sv.Unlock()
	if c, ok := sv.Containers[container]; ok {
		if p, ok := c.Processes[processId]; ok {
			p.reap()
			delete(c.ownerPod.Processes, p.inerId)
			delete(c.Processes, processId)
			if p.init {
				// TODO: kill all the other existing processes in the same container
			}
		}
		if len(c.Processes) == 0 {
			c.reap()
			delete(c.ownerPod.Containers, container)
			delete(sv.Containers, container)
		}
		if len(c.ownerPod.Containers) == 0 {
			c.ownerPod.reap()
		}
	}
}

// Exit is the wait4 information from an exited process
type Exit struct {
	Pid    int
	Status int
}

// Reap reaps all child processes for the calling process and returns their
// exit information
func Reap(wait bool) (exits []Exit, err error) {
	var (
		ws  syscall.WaitStatus
		rus syscall.Rusage
	)
	flag := syscall.WNOHANG
	if wait {
		flag = 0
	}
	for {
		pid, err := syscall.Wait4(-1, &ws, flag, &rus)
		if err != nil {
			if err == syscall.ECHILD {
				return exits, nil
			}
			return exits, err
		}
		if pid <= 0 {
			return exits, nil
		}
		exits = append(exits, Exit{
			Pid:    pid,
			Status: exitStatus(ws),
		})
	}
}

const exitSignalOffset = 128

// exitStatus returns the correct exit status for a process based on if it
// was signaled or exited cleanly
func exitStatus(status syscall.WaitStatus) int {
	if status.Signaled() {
		return exitSignalOffset + int(status.Signal())
	}
	return status.ExitStatus()
}

// find shared pod or create a new one
func (sv *Supervisor) getHyperPod(container string, spec *specs.Spec) (hp *HyperPod, err error) {
	if _, ok := sv.Containers[container]; ok {
		return nil, fmt.Errorf("The container %s is already existing", container)
	}
	if spec.Linux == nil {
		return nil, fmt.Errorf("it is not linux container config")
	}
	if containerType, ok := spec.Annotations["ocid/container_type"]; ok {
		if containerType == "container" {
			c := sv.Containers[spec.Annotations["ocid/sandbox_name"]]
			if c == nil {
				return nil, fmt.Errorf("Can't find the sandbox container")
			}
			hp = c.ownerPod
		}
	} else {
		for _, ns := range spec.Linux.Namespaces {
			if len(ns.Path) > 0 {
				if ns.Type == "mount" {
					// TODO support it!
					return nil, fmt.Errorf("Runv doesn't support shared mount namespace currently")
				}

				pidexp := regexp.MustCompile(`/proc/(\d+)/ns/*`)
				matches := pidexp.FindStringSubmatch(ns.Path)
				if len(matches) != 2 {
					return nil, fmt.Errorf("Can't find shared container with network ns path %s", ns.Path)
				}
				pid, _ := strconv.Atoi(matches[1])

				for _, c := range sv.Containers {
					if c.ownerPod != nil && pid == c.ownerPod.getNsPid() {
						if hp != nil && hp != c.ownerPod {
							return nil, fmt.Errorf("Conflict share")
						}
						hp = c.ownerPod
						break
					}
				}
				if hp == nil {
					return nil, fmt.Errorf("Can't find shared container with network ns path %s", ns.Path)
				}
			}
		}
	}
	if hp == nil {
		// use 'func() + defer' to ensure we regain the lock when createHyperPod() panic.
		// cgroup control hyperpod， resource limit only come from first container in pod
		// add containerd pid into cgroup
		glog.Infof("app first created pod into cgroup, containerd pid %v", sv.CtrdPid)
		cgManager, config, err := runcutils.NewCgManager(spec, sv.UsedSystemdCgroup)
		if err != nil {
			return nil, err
		}
		err = cgManager.Apply(sv.CtrdPid)
		if err != nil {
			glog.Errorf("apply pid into cgroup error %v", err)
		}
		err = cgManager.Set(config)
		if err != nil {
			glog.Errorf("set config for cgroup error %v", err)
		}

		func() {
			sv.Unlock()
			defer sv.Lock()
			hp, err = createHyperPod(sv.Factory, spec, sv.defaultCpus, sv.defaultMemory)
		}()
		glog.V(3).Infof("createHyperPod() returns")
		if err != nil {
			return nil, err
		}
		hp.sv = sv
		hp.CgManager = cgManager
		hp.config = config
		// recheck existed
		if _, ok := sv.Containers[container]; ok {
			go hp.reap()
			return nil, fmt.Errorf("The container %s is already existing", container)
		}
	}
	return hp, nil
}
