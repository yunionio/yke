package hosts

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/docker/docker/api/types/container"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	ConfigEnv    = "YKE_CONTENT_CONFIG"
	WriteService = "writefile"
)

func (h *Host) WriteHostFile(ctx context.Context, contName, absPath, content, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	// remove existing container. Only way it's still here is if previous deployment failed
	if err := docker.DoRemoveContainer(ctx, h.DClient, contName, h.Address); err != nil {
		return err
	}
	log.Warningf("====remove sucess: %s", contName)
	containerEnv := []string{ConfigEnv + "=" + content}
	imageCfg := &container.Config{
		Image: alpineImage,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("if [ ! -f %s ]; then echo -e \"$%s\" > %s;fi", absPath, ConfigEnv, absPath),
		},
		Env: containerEnv,
	}
	dir := filepath.Dir(absPath)
	hostCfg := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:%s", dir, dir),
		},
		Privileged: true,
	}
	if err := docker.DoRunContainer(ctx, h.DClient, imageCfg, hostCfg, contName, h.Address, WriteService, prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, h.DClient, contName, h.Address); err != nil {
		return err
	}
	log.Debugf("[%s] Successfully write config %s on node [%s]", contName, absPath, h.Address)
	return nil
}
