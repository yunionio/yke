package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/urfave/cli"

	"yunion.io/yke/pkg/types"
)

var sshCliOptions = []cli.Flag{
	cli.BoolFlag{
		Name:  "ssh-agent-auth",
		Usage: "Use SSH Agent Auth defined by SSH_AUTH_SOCK",
	},
}

func setOptionsFromCLI(c *cli.Context, config *types.KubernetesEngineConfig) (*types.KubernetesEngineConfig, error) {
	// If true... override the file.. else let file value go through
	if c.Bool("ssh-agent-auth") {
		config.SSHAgentAuth = c.Bool("ssh-agent-auth")
	}
	return config, nil
}

func resolveClusterFile(ctx *cli.Context) (string, string, error) {
	clusterFile := ctx.String("config")
	clusterFileBuff, err := ReadFile(clusterFile)
	return clusterFileBuff, clusterFile, err
}

func ReadFile(path string) (string, error) {
	fp, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to lookup current directory name: %v", err)
	}
	file, err := os.Open(fp)
	if err != nil {
		return "", fmt.Errorf("Can not find cluster configuration file: %v", err)
	}
	defer file.Close()
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}
	return string(buf), nil
}
