package command

import (
	"encoding/json"
	"os"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	profileDirFlag string = "profile-dir"
	debugLogDir    string = "debug-log-dir"
)

var hookCmd = &cli.Command{
	Name:    "hook",
	Aliases: []string{},
	Usage:   "run as oci hook",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: profileDirFlag,
		},
		&cli.StringFlag{
			Name: debugLogDir,
		},
	},
	Action: invoke,
}

func hook(c *cli.Context) error {
	// read container state from
	var state rspec.State
	err := json.NewDecoder(os.Stdin).Decode(&state)
	if err != nil {
		return err
	}
	if state.Annotations[podContainerTypeAnnotation] != "container" {
		logrus.Infof("skipping non-container type")
		return nil
	}
	return BackgroundTrace(
		state.Pid,
		c.String(profileDirFlag),
		c.String(debugLogDir),
		state.Annotations[podNamespaceAnnotation]+state.Annotations[podNameAnnotation],
		state.Annotations[podUIDAnnotation])
}
