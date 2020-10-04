/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package command

import (
	"fmt"
	"os"

	"github.com/containerd/containerd/log"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
)

var (
	logFile *os.File
)

const (
	logFileFlag  string = "log-file"
	logLevelFlag string = "log-level"

	podNameAnnotation          string = "io.kubernetes.pod.name"
	podNamespaceAnnotation     string = "io.kubernetes.pod.namespace"
	podUIDAnnotation           string = "io.kubernetes.pod.uid"
	podContainerTypeAnnotation string = "io.kubernetes.cri.container-type"
)

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: log.RFC3339NanoFixed,
		FullTimestamp:   true,
	})
}

// App returns a *cli.App instance
func App() *cli.App {
	app := cli.NewApp()
	app.Name = config.NRIPluginName
	app.Usage = "nri plugin to trace syscall using eBPF"
	app.Description = "This nri plugin traces syscalls using eBPF tracepoints for sys_enter. \n" +
		"   nri spec is currently in draft status, see here for more details: https://github.com/containerd/nri\n" +
		"   The tracing is done in two phases:\n\n" +
		"   First Phase:\n" +
		"   The [invoke] subcommand is called via nri. It processes the nri request to extract the pid of the container.\n" +
		"   Then the program calls itself with the [trace] subcommand in the background. It waits for SIGUSR1 or SIGUSR2.\n\n" +
		"   Second Phase:\n" +
		"   The [trace] subcommand compiles the eBPF program and attaches the tracepoint.\n" +
		"   It sends SIGUSR1 on success or SIGUSR2 on failure to its parent process.\n" +
		"   This program runs in the background and collects syscalls until the specified pid exits.\n\n" +
		"   Important:\n" +
		"   You need to mount the bpf fs mounted: \"mount bpffs /sys/fs/bpf -t bpf\""

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        logLevelFlag,
			DefaultText: "debug",
			Aliases:     []string{"l"},
			Usage:       "set the logging level [trace, debug, info, warn, error, fatal, panic]",
		},
		&cli.StringFlag{
			Name:    logFileFlag,
			Aliases: []string{"f"},
			Usage:   "if specified, logs are written to this file instead of stdout",
		},
	}
	app.Before = func(ctx *cli.Context) error {
		l := ctx.String("log-level")
		if l != "" {
			lvl, err := logrus.ParseLevel(l)
			if err != nil {
				return err
			}
			logrus.SetLevel(lvl)
		}
		lf := ctx.String("log-file")
		if lf != "" {
			var err error
			logFile, err = os.OpenFile(lf, os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				return fmt.Errorf("could not open log file: %s", err)
			}
			logrus.SetOutput(logFile)
		}
		return nil
	}
	app.After = func(ctx *cli.Context) error {
		if logFile != nil {
			return logFile.Close()
		}
		return nil
	}
	app.Commands = cli.Commands{
		versionCmd,
		invokeCmd,
		hookCmd,
		traceCmd,
	}
	return app
}
