package command

import (
	"github.com/urfave/cli/v2"
	"sigs.k8s.io/seccomp-operator/internal/pkg/version"
)

var versionCmd = &cli.Command{
	Name:    "version",
	Aliases: []string{"v"},
	Usage:   "display detailed version information",
	Flags:   []cli.Flag{},
	Action: func(c *cli.Context) error {
		v := version.Get()
		res := v.String()
		print(res)
		return nil
	},
}
