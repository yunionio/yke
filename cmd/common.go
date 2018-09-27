package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/urfave/cli"

	"yunion.io/x/yke/pkg/types"
)

var commonFlags = []cli.Flag{
	cli.BoolFlag{
		Name:  "ssh-agent-auth",
		Usage: "Use SSH Agent Auth defined by SSH_AUTH_SOCK",
	},
	cli.BoolFlag{
		Name:  "ignore-docker-version",
		Usage: "Disable Docker version check",
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
	fp, err := filepath.Abs(clusterFile)
	if err != nil {
		return "", "", fmt.Errorf("Failed to lookup current directory name: %v", err)
	}
	file, err := os.Open(fp)
	if err != nil {
		return "", "", fmt.Errorf("Can't find cluster configuration file: %v", err)
	}
	defer file.Close()
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		return "", "", fmt.Errorf("Failed to read file: %v", err)
	}
	clusterFileBuff := string(buf)
	return clusterFileBuff, clusterFile, nil
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
