module sigs.k8s.io/seccomp-operator

go 1.15

require (
	github.com/containerd/containerd v1.4.1
	github.com/containerd/nri v0.0.0-20200903033618-5e52908d1c3c
	github.com/containers/common v0.21.0 // can be built with the `seccomp` build tag to support more features
	github.com/crossplane/crossplane-runtime v0.9.0
	github.com/go-logr/logr v0.2.1
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/opencontainers/runtime-spec v1.0.3-0.20200710190001-3e4195d92445
	github.com/pkg/errors v0.9.1
	github.com/seccomp/containers-golang v0.6.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/urfave/cli/v2 v2.2.0
	github.com/willf/bitset v1.1.11 // indirect
	golang.org/x/net v0.0.0-20200930145003-4acb6c075d10 // indirect
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f // indirect
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/release v0.4.1
	sigs.k8s.io/controller-runtime v0.6.3
)
