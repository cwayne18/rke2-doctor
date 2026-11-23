// Command rke2-doctor diagnoses common RKE2 node and cluster health issues
// and can export a redacted support bundle for filing support tickets.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"k8s.io/client-go/kubernetes"

	"github.com/cwayne18/rke2-doctor/internal/bundle"
	"github.com/cwayne18/rke2-doctor/internal/check"
	"github.com/cwayne18/rke2-doctor/internal/checks/cluster"
	"github.com/cwayne18/rke2-doctor/internal/checks/config"
	"github.com/cwayne18/rke2-doctor/internal/checks/host"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	app := &cli.App{
		Name:    "rke2-doctor",
		Usage:   "diagnose RKE2 node and cluster health",
		Version: version,
		Commands: []*cli.Command{
			runCommand(),
			bundleCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runCommand() *cli.Command {
	return &cli.Command{
		Name:  "run",
		Usage: "run diagnostic checks and print a report",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "category", Usage: "only run checks in this category (host, config, cluster)"},
			&cli.BoolFlag{Name: "json", Usage: "output machine-readable JSON instead of a text report"},
			&cli.BoolFlag{Name: "no-color", Usage: "disable ANSI colors in text output"},
			&cli.StringFlag{Name: "kubeconfig", Usage: "path to kubeconfig for cluster-wide checks (default: /etc/rancher/rke2/rke2.yaml if present)"},
		},
		Action: func(c *cli.Context) error {
			reg := buildRegistry(c.String("kubeconfig"))
			results := check.Run(context.Background(), reg.ByCategory(c.String("category")))

			if c.Bool("json") {
				if err := check.WriteJSON(os.Stdout, results); err != nil {
					return err
				}
			} else {
				check.WriteText(os.Stdout, results, !c.Bool("no-color"))
			}

			os.Exit(check.ExitCode(check.WorstStatus(results)))
			return nil
		},
	}
}

func bundleCommand() *cli.Command {
	return &cli.Command{
		Name:  "bundle",
		Usage: "collect a redacted support bundle (config, logs, diagnostic report)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Value: "rke2-support-bundle.tar.gz", Usage: "output archive path"},
			&cli.StringFlag{Name: "kubeconfig", Usage: "path to kubeconfig for cluster-wide checks"},
		},
		Action: func(c *cli.Context) error {
			reg := buildRegistry(c.String("kubeconfig"))
			results := check.Run(context.Background(), reg.All())

			var reportBuf bytes.Buffer
			if err := check.WriteJSON(&reportBuf, results); err != nil {
				return fmt.Errorf("rendering report: %w", err)
			}

			out := c.String("output")
			if err := bundle.Write(out, bundle.DefaultSources(), "doctor-report.json", reportBuf.Bytes()); err != nil {
				return fmt.Errorf("writing bundle: %w", err)
			}
			fmt.Printf("wrote support bundle to %s\n", out)
			return nil
		},
	}
}

// buildRegistry assembles all available checks. Cluster-wide checks are
// included with a nil client (and will report Skip) if no kubeconfig is
// found, so `run`/`bundle` always work on a bare node.
func buildRegistry(kubeconfigFlag string) *check.Registry {
	reg := check.NewRegistry()
	reg.Register(
		host.NewKernelModuleCheck(),
		host.NewSysctlCheck(),
		host.NewDiskSpaceCheck(),
		host.NewSwapCheck(),
		host.NewCertExpiryCheck(),
		config.NewLintCheck(),
	)

	var client kubernetes.Interface
	if kubeconfig := resolveKubeconfig(kubeconfigFlag); kubeconfig != "" {
		if c, err := cluster.NewClientFromKubeconfig(kubeconfig); err == nil {
			client = c
		}
	}
	reg.Register(
		&cluster.NodeReadyCheck{Client: client},
		&cluster.PodHealthCheck{Client: client},
	)

	return reg
}

func resolveKubeconfig(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	const defaultPath = "/etc/rancher/rke2/rke2.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}
