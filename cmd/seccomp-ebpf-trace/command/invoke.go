package command

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/containerd/nri/skel"
	nritypes "github.com/containerd/nri/types/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
	"sigs.k8s.io/seccomp-operator/internal/pkg/tracer/nri"
)

var invokeCmd = &cli.Command{
	Name:    "invoke",
	Aliases: []string{},
	Usage:   "invoke nri plugin",
	Flags:   []cli.Flag{},
	Action:  invoke,
}

func invoke(c *cli.Context) error {
	logrus.Info("starting NRI Seccomp Trace plugin")
	// extract PID via nri plugin
	nri := nri.New()
	err := skel.Run(context.Background(), nri)
	if err != nil {
		return errors.Wrap(err, "error running nri plugin")
	}
	cfg, err := nri.Config()
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}
	req := nri.Request()
	if req == nil {
		return fmt.Errorf("missing nri request")
	}
	if shouldStopTrace(req) {
		// TODO: close prog via eBPF fs?
		return nil
	} else if shouldStartTrace(req) {
		return BackgroundTrace(nri.GetPID(), cfg.ProfileDir, cfg.DebugLogDir, Pod(req), PodUID(req))
	}
	return nil
}

// BackgroundTrace starts a subprocess which runs the tracer.
// It waits for a SIGUSR1 from the child and returns once received (or timeouts)
func BackgroundTrace(pid int, profileDir, debugLogDir, podName, podUID string) error {
	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil,
			nil,
		},
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2)
	executable, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "cannot determine executable")
	}
	args := []string{config.NRIPluginName}
	if debugLogDir != "" {
		args = append(args, "--"+logFileFlag, filepath.Join(debugLogDir, fmt.Sprintf("seccomp-log.%s.%s.log", podName, podUID)))
	}
	args = append(args, traceCmd.Name, "--"+pidFlag, strconv.Itoa(pid))
	if profileDir != "" {
		args = append(args, "--"+outFileFlag, filepath.Join(profileDir, fmt.Sprintf("seccomp-profile.%s.%s.json", podName, podUID)))
	}
	process, err := os.StartProcess(executable, args, attr)
	if err != nil {
		return errors.Wrap(err, "cannot execute child process")
	}
	defer func() {
		err = process.Release()
		if err != nil {
			logrus.Error("error releasing child process: %s", err)
		}
	}()

	select {
	// Check which signal we received and act accordingly.
	case s := <-sig:
		logrus.Info("received signal", "signal", s)
		switch s {
		case syscall.SIGUSR1:
			// Child started tracing. We can safely detach.
			break
		case syscall.SIGUSR2:
			return errors.New("error while child-process init")
		default:
			return errors.Errorf("unexpected signal from child: %v", s)
		}

	// The timeout kicked in. Kill the child and return the sad news.
	case <-time.After(time.Second * 20):
		err := process.Kill()
		if err != nil {
			logrus.Error("error killing child process: %s", err)
		}
		return errors.Errorf("child process timed out")
	}
	return nil
}

func shouldStartTrace(req *nritypes.Request) bool {
	if req.State != nritypes.Create {
		return false
	}
	t, ok := req.Spec.Annotations[podContainerTypeAnnotation]
	if !ok {
		return false
	}
	return t == "container"
}

func shouldStopTrace(req *nritypes.Request) bool {
	if req.State != nritypes.Delete {
		return false
	}
	t, ok := req.Spec.Annotations[podContainerTypeAnnotation]
	if !ok {
		return false
	}
	return t == "container"
}

func PodUID(req *nritypes.Request) string {
	return req.Labels[podUIDAnnotation]
}

func Pod(req *nritypes.Request) string {
	ns := req.Labels[podNamespaceAnnotation]
	pod := req.Labels[podNameAnnotation]
	return fmt.Sprintf("%s.%s", ns, pod)
}
