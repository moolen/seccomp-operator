package nri

import (
	"context"
	"encoding/json"
	"fmt"

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

const (
	podNameAnnotation      string = "io.kubernetes.pod.name"
	podNamespaceAnnotation string = "io.kubernetes.pod.namespace"
	podUIDAnnotation       string = "io.kubernetes.pod.uid"
)

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

// TODO: move out
func (c *Plugin) PodUID() string {
	return c.req.Labels[podUIDAnnotation]
}

// TODO: move out
func (c *Plugin) Pod() string {
	ns := c.req.Labels[podNamespaceAnnotation]
	pod := c.req.Labels[podNameAnnotation]
	return fmt.Sprintf("%s.%s", ns, pod)
}

// TODO: move out
func (c *Plugin) ShouldStartTrace() bool {
	if c.req.State != types.Create {
		return false
	}
	t, ok := c.req.Spec.Annotations["io.kubernetes.cri.container-type"]
	if !ok {
		return false
	}
	return t == "container"
}

// TODO: move out
func (c *Plugin) ShouldStopTrace() bool {
	if c.req.State != types.Delete {
		return false
	}
	t, ok := c.req.Spec.Annotations["io.kubernetes.cri.container-type"]
	if !ok {
		return false
	}
	return t == "container"
}

// Invoke starts the eBPF tracer
func (c *Plugin) Invoke(ctx context.Context, r *types.Request) (*types.Result, error) {
	c.req = r
	logrus.Infof("nri request: %#v", r)
	logrus.Infof("nri spec: %#v", r.Spec)
	return r.NewResult(c.Type()), nil
}
