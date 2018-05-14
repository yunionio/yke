package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/urfave/cli"

	"yunion.io/yke/pkg/cluster"
	"yunion.io/yke/pkg/pki"
)

var (
	gitVersion   string = "v1.6.2+$Format:%h$"
	gitCommit    string = "$Format:%H$"
	gitTreeState string = "not a git tree"
	buildDate    string = "1970-01-01T00:00:00Z"
)

type VersionInfo struct {
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

func (i VersionInfo) String() string {
	bs, _ := json.MarshalIndent(i, "", "  ")
	return string(bs)
}

func Version() VersionInfo {
	return VersionInfo{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func VersionCommand() cli.Command {
	versionFlags := []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "Specify an alternate cluster YAML file",
			Value:  pki.ClusterConfig,
			EnvVar: "YKE_CONFIG",
		},
	}
	return cli.Command{
		Name:   "version",
		Usage:  "Show cluster Kubernetes version",
		Action: getClusterVersion,
		Flags:  versionFlags,
	}
}

func getClusterVersion(ctx *cli.Context) error {
	localKubeConfig := pki.GetLocalKubeConfig(ctx.String("config"), "")
	// not going to use a k8s dialer here.. this is a CLI command
	serverVersion, err := cluster.GetK8sVersion(localKubeConfig, nil)
	if err != nil {
		return err
	}
	fmt.Printf("Server Version: %s\n", serverVersion)
	return nil
}
