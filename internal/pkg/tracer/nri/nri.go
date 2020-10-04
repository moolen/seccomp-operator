package nri

import (
	"context"
	"encoding/json"

	types "github.com/containerd/nri/types/v1"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
)

// Plugin implements the NRI Plugin spec
// it starts an eBPF tracer in the background to trace syscalls
type Plugin struct {
	req *types.Request
}

// PluginConfig is the nri plugin config
type PluginConfig struct {
	Version     string `json:"version"`
	ProfileDir  string `json:"profileDir"`
	DebugLogDir string `json:"debugLogDir"`
}

// New creates a new Plugin
func New() *Plugin {
	return &Plugin{}
}

// Type returns the plugin name
// this is matched with the nri plugin configuration in
// /etc/nri/resource.d/*.conf and /etc/nri/conf.json
func (c *Plugin) Type() string {
	return config.NRIPluginName
}

// GetPID returns the PID submitted via nri request
func (c *Plugin) GetPID() int {
	return c.req.Pid
}

func (c *Plugin) Config() (*PluginConfig, error) {
	var cfg PluginConfig
	err := json.Unmarshal(c.req.Conf, &cfg)
	return &cfg, err
}

func (c *Plugin) Request() *types.Request {
	return c.req
}

// Invoke starts the eBPF tracer
func (c *Plugin) Invoke(ctx context.Context, r *types.Request) (*types.Result, error) {
	c.req = r
	logrus.Infof("nri request: %#v", r)
	logrus.Infof("nri spec: %#v", r.Spec)
	return r.NewResult(c.Type()), nil
}
