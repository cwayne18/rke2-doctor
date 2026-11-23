# rke2-doctor

`rke2-doctor` is a standalone diagnostic CLI for [RKE2](https://docs.rke2.io/)
clusters. It runs read-only checks against a node (and, optionally, the
Kubernetes API) to catch problems *before* they cause an outage, and can
produce a redacted support bundle to attach to a support ticket.

It is a single static binary with no dependency on an in-cluster
operator/CRDs — install it, run it, remove it.

## Why not `kube-bench` / `cis-operator` / `rke2 check-config`?

Those tools already cover specific slices well and `rke2-doctor` is meant to
complement, not replace, them:

- `rke2 check-config` (inherited from k3s) validates kernel/cgroup
  *prerequisites* before RKE2 is even installed.
- `kube-bench` / Rancher's `cis-operator` validate CIS benchmark
  *compliance*.

`rke2-doctor` instead focuses on **operational health of an already-running
node/cluster**: certificate expiry, disk pressure, config.yaml footguns,
control-plane/node/pod health, and a one-shot redacted support bundle —
things that tend to bite operators weeks or months after a cluster is
already live.

## Install

```sh
go install github.com/cwayne18/rke2-doctor/cmd/rke2-doctor@latest
```

Or build from source:

```sh
git clone https://github.com/cwayne18/rke2-doctor
cd rke2-doctor
make build
```

## Usage

Run every check and print a human-readable report:

```sh
rke2-doctor run
```

Run only one category (`host`, `config`, or `cluster`):

```sh
rke2-doctor run --category host
```

Machine-readable output (for CI/cron/alerting pipelines). Exit codes are
`0` (all pass), `1` (warnings present), `2` (at least one failure):

```sh
rke2-doctor run --json
```

Collect a redacted support bundle (config, recent service logs, and the
diagnostic report) to attach to a support ticket:

```sh
rke2-doctor bundle -o rke2-support-bundle.tar.gz
```

Cluster-wide checks (node readiness, pod health in kube-system) activate
automatically if `/etc/rancher/rke2/rke2.yaml` exists, or via `--kubeconfig`:

```sh
rke2-doctor run --kubeconfig ~/.kube/config
```

## Checks (current)

| Category | Check | What it catches |
|---|---|---|
| host | `kernel-modules` | missing `overlay`/`br_netfilter` modules |
| host | `network-sysctls` | bridged traffic / ip_forward sysctls not set |
| host | `disk-space` | low free space under RKE2 data directories |
| host | `swap-enabled` | swap enabled (flagged for review) |
| host | `certificate-expiry` | TLS certs expiring soon or already expired |
| config | `config-lint` | insecure `write-kubeconfig-mode`, empty `tls-san`, overlapping `cluster-cidr`/`service-cidr` |
| cluster | `node-ready` | NotReady nodes, disk/memory/PID pressure |
| cluster | `pod-health` | pending/failed/crash-looping pods in `kube-system` |

More checks (control-plane/etcd health, log pattern scanning, a
fleet-wide DaemonSet mode) are on the roadmap — contributions welcome.

## Design

Each diagnostic implements a small `Check` interface
(`internal/check.Check`) and is registered into a `Registry`. Checks are
independent, read-only, and recover from panics so one broken check can't
abort a run. See `internal/check/check.go` for the core abstraction and
`internal/checks/*` for implementations.

## Development

```sh
make build   # go build ./...
make test    # go test ./... -race -cover
make lint    # go vet + gofmt -l
```

## License

Apache 2.0, see [LICENSE](LICENSE).
