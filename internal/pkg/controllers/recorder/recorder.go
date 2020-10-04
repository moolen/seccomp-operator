package recorder

// 0. @main start a server that listens /var/lib/kubelet/seccomp/operator/recorder.sock
// 1. put the `seccomp-trace` binary to `/opt/nri/bin/seccomp-trace`
// 2. place a `/etc/nri/conf.json` (containerd 1.4.0+) or `/etc/nri/resource.d` (TBD) with:
// 3. do something with these profiles
