package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	types "github.com/seccomp/containers-golang"
	"github.com/sirupsen/logrus"

	"github.com/iovisor/gobpf/bcc"
	"github.com/pkg/errors"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type Tracer struct {
	pid     int
	outFile string
	mod     *bcc.Module
	perfMap *bcc.PerfMap
	f       *os.File
}

func NewTracer(pid int, outFile string) (*Tracer, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid trace pid: %d", pid)
	}
	return &Tracer{
		pid:     pid,
		outFile: outFile,
	}, nil
}

// Init initializes the eBPF module and loads
func (t *Tracer) Init() error {
	if err := modprobe("kheaders"); err != nil {
		logrus.Infof("loading kernel module `kheaders` failed, continuing in hope kernel headers reside on disk: %s", err)
	}
	src := strings.Replace(source, "$PARENT_PID", strconv.Itoa(t.pid), -1)
	t.mod = bcc.NewModule(src, []string{})
	enterTrace, err := t.mod.LoadTracepoint("enter_trace")
	if err != nil {
		return errors.Wrap(err, "error loading tracepoint")
	}
	checkExit, err := t.mod.LoadTracepoint("check_exit")
	if err != nil {
		return errors.Wrap(err, "error loading tracepoint")
	}
	err = t.mod.AttachTracepoint("raw_syscalls:sys_enter", enterTrace)
	if err != nil {
		return errors.Wrap(err, "error attaching to tracepoint")
	}
	// TODO: handle exit through nri interface (?)
	return t.mod.AttachTracepoint("sched:sched_process_exit", checkExit)
}

// Run starts the perf map polling
// and returns when the container is finished
func (t *Tracer) Run() error {
	var wg sync.WaitGroup
	var err error
	table := bcc.NewTable(t.mod.TableId("events"), t.mod)
	channel := make(chan []byte)
	t.perfMap, err = bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		return errors.Wrap(err, "error initializing perf map")
	}
	syscalls := make(map[string]int, 303)

	// Initialize the wait group used to wait for the tracing to be finished.
	wg.Add(1)
	go func() {
		defer wg.Done()
		recordSyscalls := true // TODO: dig into runc: there's no prctl syscall here
		var e event
		for data := range channel {
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
				// Return in case of an error. Otherwise, we
				// could miss stop event and run into an
				// infinite loop.
				logrus.Errorf("failed to decode received data %q: %s\n", data, err)
				return
			}

			// The BPF program is done tracing, so we can stop
			// reading from the perf buffer.
			if e.StopTracing {
				logrus.Info("stopping reader goroutine")
				return
			}

			name, err := syscallIDtoName(e.ID)
			if err != nil {
				logrus.Errorf("error getting the name for syscall ID %d", e.ID)
			}
			// Syscalls are not recorded until prctl() is called. The first
			// invocation of prctl is guaranteed to happen by the supported
			// OCI runtimes (i.e., runc and crun) as it's being called when
			// setting the seccomp profile.
			// if name == "prctl" {
			// 	logrus.Info("received prctl. start recording")
			// 	recordSyscalls = true
			// }

			if recordSyscalls {
				syscalls[name]++
			}
		}
	}()
	t.perfMap.Start()
	wg.Wait()

	// TODO: this seems buggy
	// perf_reader_poll blocks indefinitely
	go t.perfMap.Stop()

	logrus.Infof("generating seccomp profile %q", t.outFile)
	if err := generateProfile(syscalls, t.outFile); err != nil {
		return errors.Wrap(err, "error generating final seccomp profile")
	}
	return nil
}

// Close closes the eBPF fds
func (t *Tracer) Close() {
	t.mod.Close()
}

// generateProfile merges the seccomp profile from profilePath and the syscall map
func generateProfile(syscalls map[string]int, profilePath string) error {
	outputProfile := types.Seccomp{}
	inputProfile := types.Seccomp{}

	input, err := ioutil.ReadFile(profilePath)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "error reading input file")
	}
	if err == nil {
		err = json.Unmarshal(input, &inputProfile)
		if err != nil {
			return errors.Wrap(err, "error parsing input file")
		}
	}

	var names []string
	for syscallName, syscallID := range syscalls {
		if syscallID > 0 {
			if !syscallInProfile(&inputProfile, syscallName) {
				names = append(names, syscallName)
			}
		}
	}
	sort.Strings(names)

	outputProfile = inputProfile
	outputProfile.DefaultAction = types.ActErrno

	if err := appendArchIfNotAlreadyIncluded(runtime.GOARCH, &outputProfile); err != nil {
		return errors.Wrap(err, "appending architecture to output profile")
	}

	outputProfile.Syscalls = append(outputProfile.Syscalls, &types.Syscall{
		Action: types.ActAllow,
		Names:  names,
		Args:   []*types.Arg{},
	})

	sJSON, err := json.Marshal(outputProfile)
	if err != nil {
		return errors.Wrap(err, "error writing seccomp profile")
	}
	if err := ioutil.WriteFile(profilePath, sJSON, 0644); err != nil {
		return errors.Wrap(err, "error writing seccomp profile")
	}
	return nil
}

// syscallInProfile checks if the input profile contains the syscall..
func syscallInProfile(profile *types.Seccomp, syscall string) bool {
	for _, s := range profile.Syscalls {
		if s.Name == syscall {
			return true
		}
		for _, name := range s.Names {
			if name == syscall {
				return true
			}
		}
	}
	return false
}

func appendArchIfNotAlreadyIncluded(goArch string, profile *types.Seccomp) error {
	targetArch, err := types.GoArchToSeccompArch(goArch)
	if err != nil {
		return errors.Wrap(err, "determine target architecture")
	}
	for _, arch := range profile.Architectures {
		if arch == targetArch {
			// architecture already part of the profile
			return nil
		}
	}
	profile.Architectures = append(profile.Architectures, targetArch)
	return nil
}

// syscallIDtoName returns the syscall name for the specified ID.
func syscallIDtoName(id uint32) (string, error) {
	return seccomp.ScmpSyscall(id).GetName()
}

// modprobe the specified module.
func modprobe(module string) error {
	bin, err := exec.LookPath("modprobe")
	if err != nil {
		// Fallback to `/usr/sbin/modprobe`.  The environment may be
		// empty.  If that doesn't exist either, we'll fail below.
		bin = "/usr/sbin/modprobe"
	}
	return exec.Command(bin, module).Run()
}
