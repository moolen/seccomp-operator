package command

import (
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"sigs.k8s.io/seccomp-operator/internal/pkg/tracer/ebpf"
)

const (
	skipSignalFlag string = "skip-signal"
	pidFlag        string = "pid"
	outFileFlag    string = "out-file"
)

var traceCmd = &cli.Command{
	Name:    "trace",
	Aliases: []string{},
	Usage:   "starts a tracer",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  skipSignalFlag,
			Usage: "skip sending signal to parent",
		},
		&cli.IntFlag{
			Name:  pidFlag,
			Usage: "pid to trace",
		},
		&cli.StringFlag{
			Name:  outFileFlag,
			Usage: "output file",
		},
	},
	Action: trace,
}

func trace(c *cli.Context) error {
	logrus.Info("setting up tracer")
	t, err := setupTracer(
		c.Bool(skipSignalFlag),
		c.Int(pidFlag),
		c.String(outFileFlag))
	if err != nil {
		logrus.Error("error setup tracer: %s", err)
		return err
	}
	defer func() {
		t.Close()
		os.Exit(0) // TODO: hack to kill perfMap.Close
	}()
	logrus.Info("starting tracer")
	err = t.Run()
	if err != nil {
		logrus.Error("error running tracer: %s", err)
		return err
	}
	logrus.Info("done tracing")
	return nil
}

// setupTracer implements signal handling with parent
func setupTracer(skipSignal bool, pid int, outFile string) (*ebpf.Tracer, error) {
	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)
	if err != nil {
		logrus.Error("cannot find parent process: %s", err)
	}
	signalSent := false
	defer func() {
		if !signalSent && !skipSignal {
			logrus.Info("Sending SIGUSR2 to parent", "ppid", ppid)
			if err := parentProcess.Signal(syscall.SIGUSR2); err != nil {
				logrus.Error("error sending signal to parent process: %s", err)
			}
		}
	}()

	// try to setup tracer befor signaling the parent
	tracer, err := ebpf.NewTracer(pid, outFile)
	if err != nil {
		return nil, errors.Wrap(err, "error creating tracer")
	}
	err = tracer.Init()
	if err != nil {
		return nil, errors.Wrap(err, "error initializing tracer")
	}
	if !skipSignal {
		// send OK signal to parent
		err = parentProcess.Signal(syscall.SIGUSR1)
		if err != nil {
			return nil, errors.Wrap(err, "error sending signal to parent")
		}
	}
	signalSent = true
	return tracer, nil
}
