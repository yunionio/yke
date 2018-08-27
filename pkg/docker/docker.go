package docker

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	ref "github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	ytypes "yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
	"yunion.io/yunioncloud/pkg/util/sets"
)

func DoRunContainer(ctx context.Context, dClient *client.Client, imageCfg *container.Config, hostCfg *container.HostConfig, containerName, hostname, plane string, prsMap map[string]ytypes.PrivateRegistry) error {
	container, err := dClient.ContainerInspect(ctx, containerName)
	if err != nil {
		if !client.IsErrNotFound(err) {
			return err
		}
		if err := UseLocalOrPull(ctx, dClient, hostname, imageCfg.Image, plane, prsMap); err != nil {
			return err
		}
		resp, err := dClient.ContainerCreate(ctx, imageCfg, hostCfg, nil, containerName)
		if err != nil {
			return fmt.Errorf("Failed to create [%s] container on host [%s]: %v", containerName, hostname, err)
		}
		if err := dClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
			return fmt.Errorf("Failed to start [%s] container on host [%s]: %v", containerName, hostname, err)
		}
		log.Infof("[%s] Successfully started [%s] container on host [%s]", plane, containerName, hostname)
		return nil
	}
	// Check for upgrades
	if container.State.Running {
		log.Debugf("[%s] Container [%s] is already running on host [%s]", plane, containerName, hostname)
		isUpgradable, err := IsContainerUpgradable(ctx, dClient, imageCfg, containerName, hostname, plane)
		if err != nil {
			return err
		}
		if isUpgradable {
			return DoRollingUpdateContainer(ctx, dClient, imageCfg, hostCfg, containerName, hostname, plane, prsMap)
		}
		return nil
	}
	// Start if not running
	log.Debugf("[%s] Starting stopped container [%s] on host [%s]", plane, containerName, hostname)
	if err := dClient.ContainerStart(ctx, container.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("Failed to start [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	log.Infof("[%s] Successfully started [%s] container on host [%s]", plane, containerName, hostname)
	return nil
}

func DoRollingUpdateContainer(ctx context.Context, dClient *client.Client, imageCfg *container.Config, hostCfg *container.HostConfig, containerName, hostname, plane string, prsMap map[string]ytypes.PrivateRegistry) error {
	log.Debugf("[%s] Checking for deployed [%s]", plane, containerName)
	isRunning, err := IsContainerRunning(ctx, dClient, hostname, containerName, false)
	if err != nil {
		return err
	}
	if !isRunning {
		log.Debugf("[%s] Container %s is not running on host [%s]", plane, containerName, hostname)
		return nil
	}
	err = UseLocalOrPull(ctx, dClient, hostname, imageCfg.Image, plane, prsMap)
	if err != nil {
		return err
	}
	log.Debugf("[%s] Stopping old container", plane)
	oldContainerName := "old-" + containerName
	if err := StopRenameContainer(ctx, dClient, hostname, containerName, oldContainerName); err != nil {
		return err
	}
	log.Debugf("[%s] Successfully stopped old container %s on host [%s]", plane, containerName, hostname)
	_, err = CreateContainer(ctx, dClient, hostname, containerName, imageCfg, hostCfg)
	if err != nil {
		return fmt.Errorf("Failed to create [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	if err := StartContainer(ctx, dClient, hostname, containerName); err != nil {
		return fmt.Errorf("Failed to start [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	log.Infof("[%s] Successfully updated [%s] container on host [%s]", plane, containerName, hostname)
	return RemoveContainer(ctx, dClient, hostname, oldContainerName)
}

func DoRemoveContainer(ctx context.Context, dClient *client.Client, containerName, hostname string) error {
	log.Debugf("[remove/%s] Checking if container is running on host [%s]", containerName, hostname)
	// not using the wrapper to check if the error is a NotFound error
	_, err := dClient.ContainerInspect(ctx, containerName)
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Debugf("[remove/%s] Container doesn't exist on host [%s]", containerName, hostname)
			return nil
		}
		return err
	}
	log.Debugf("[remove/%s] Stopping container on host [%s]", containerName, hostname)
	err = StopContainer(ctx, dClient, hostname, containerName)
	if err != nil {
		return err
	}
	log.Infof("[remove/%s] Successfully removed container on host [%s]", containerName, hostname)
	return nil
}

func IsContainerRunning(ctx context.Context, dClient *client.Client, hostname, containerName string, all bool) (bool, error) {
	log.Debugf("Checking if container [%s] is running on host [%s]", containerName, hostname)
	containers, err := dClient.ContainerList(ctx, types.ContainerListOptions{All: all})
	if err != nil {
		return false, fmt.Errorf("Can't get Docker containers for host [%s]: %v", hostname, err)
	}
	for _, container := range containers {
		if container.Names[0] == "/"+containerName {
			return true, nil
		}
	}
	return false, nil
}

func localImageExists(ctx context.Context, dClient *client.Client, hostname string, containerImage string) (bool, error) {
	log.Debugf("Checking if image [%s] exists on host [%s]", containerImage, hostname)
	_, _, err := dClient.ImageInspectWithRaw(ctx, containerImage)
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Debugf("Image [%s] does not exist on host [%s]: %v", containerImage, hostname, err)
			return false, nil
		}
		return false, fmt.Errorf("Error checking if image [%s] exists on host [%s]: %v", containerImage, hostname, err)
	}
	log.Debugf("Image [%s] exists on host [%s]", containerImage, hostname)
	return true, nil
}

func pullImage(ctx context.Context, dClient *client.Client, hostname string, containerImage string, prsMap map[string]ytypes.PrivateRegistry) error {
	pullOptions := types.ImagePullOptions{}

	regAuth, prURL, err := GetImageRegistryConfig(containerImage, prsMap)
	if err != nil {
		return err
	}
	if regAuth != "" && prURL == DockerRegistryURL {
		pullOptions.PrivilegeFunc = tryRegistryAuth(prsMap[prURL])
	}
	pullOptions.RegistryAuth = regAuth

	out, err := dClient.ImagePull(ctx, containerImage, pullOptions)
	if err != nil {
		return fmt.Errorf("Can't pull Docker image [%s] for host [%s]: %v", containerImage, hostname, err)
	}
	defer out.Close()
	io.Copy(os.Stdout, out)
	return nil
}

func UseLocalOrPull(ctx context.Context, dClient *client.Client, hostname string, containerImage string, plane string, prsMap map[string]ytypes.PrivateRegistry) error {
	log.Debugf("[%s] Checking image [%s] on host [%s]", plane, containerImage, hostname)
	imageExists, err := localImageExists(ctx, dClient, hostname, containerImage)
	if err != nil {
		return err
	}
	if imageExists {
		log.Debugf("[%s] No pull necessary, image [%s] exists on host [%s]", plane, containerImage, hostname)
		return nil
	}
	log.Infof("[%s] Pulling image [%s] on host [%s]", plane, containerImage, hostname)
	if err := pullImage(ctx, dClient, hostname, containerImage, prsMap); err != nil {
		return err
	}
	log.Infof("[%s] Successfully pulled image [%s] on host [%s]", plane, containerImage, hostname)
	return nil
}

func RemoveContainer(ctx context.Context, dClient *client.Client, hostname, containerName string) error {
	var err error
	for i := 0; i < 3; i++ {
		err = dClient.ContainerRemove(ctx, containerName, types.ContainerRemoveOptions{Force: true})
		if err == nil {
			break
		}
		log.Errorf("Remove container [%s] for host [%s], times: %d, error: %v", containerName, hostname, i+1, err)
	}
	if err != nil {
		return fmt.Errorf("Can't remove Docker container [%s] for host [%s]: %v", containerName, hostname, err)
	}
	return nil
}

func StopContainer(ctx context.Context, dClient *client.Client, hostname, containerName string) error {
	err := dClient.ContainerStop(ctx, containerName, nil)
	if err != nil {
		return fmt.Errorf("Can't stop Docker container [%s] for host [%s]: %v", containerName, hostname, err)
	}
	return nil
}

func RenameContainer(ctx context.Context, dClient *client.Client, hostname, oldContainerName, newContainerName string) error {
	err := dClient.ContainerRename(ctx, oldContainerName, newContainerName)
	if err != nil {
		return fmt.Errorf("Can't rename Docker container [%s] for host [%s]: %v", oldContainerName, hostname, err)
	}
	return nil
}

func StartContainer(ctx context.Context, dClient *client.Client, hostname, containerName string) error {
	if err := dClient.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("Failed to start [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	return nil
}

func CreateContainer(ctx context.Context, dClient *client.Client, hostname, containerName string, imageCfg *container.Config, hostCfg *container.HostConfig) (container.ContainerCreateCreatedBody, error) {
	created, err := dClient.ContainerCreate(ctx, imageCfg, hostCfg, nil, containerName)
	if err != nil {
		return container.ContainerCreateCreatedBody{}, fmt.Errorf("Failed to create [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	return created, nil
}

func InspectContainer(ctx context.Context, dClient *client.Client, hostname, containerName string) (types.ContainerJSON, error) {
	inspection, err := dClient.ContainerInspect(ctx, containerName)
	if err != nil {
		return types.ContainerJSON{}, fmt.Errorf("Failed to inspect [%s] container on host [%s]: %v", containerName, hostname, err)
	}
	return inspection, nil
}

func StopRenameContainer(ctx context.Context, dClient *client.Client, hostname, oldContainerName, newContainerName string) error {
	if err := StopContainer(ctx, dClient, hostname, oldContainerName); err != nil {
		return err
	}
	if err := WaitForContainer(ctx, dClient, hostname, oldContainerName); err != nil {
		return nil
	}
	return RenameContainer(ctx, dClient, hostname, oldContainerName, newContainerName)
}

func WaitForContainer(ctx context.Context, dClient *client.Client, hostname, containerName string) error {
	statusCh, errCh := dClient.ContainerWait(ctx, containerName, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("Error waiting for container [%s] on host [%s]: %v", containerName, hostname, err)
		}
	case <-statusCh:
	}
	return nil
}

func IsContainerUpgradable(ctx context.Context, dClient *client.Client, imageCfg *container.Config, containerName, hostname, plane string) (bool, error) {
	log.Debugf("[%s] Checking if container [%s] is eligible for upgrade on host [%s]", plane, containerName, hostname)
	// this should be mode to a higher layer.

	containerInspect, err := InspectContainer(ctx, dClient, hostname, containerName)
	if err != nil {
		return false, err
	}
	if containerInspect.Config.Image != imageCfg.Image ||
		!sliceEqualsIgnoreOrder(containerInspect.Config.Entrypoint, imageCfg.Entrypoint) ||
		!sliceEqualsIgnoreOrder(containerInspect.Config.Cmd, imageCfg.Cmd) {
		log.Debugf("[%s] Container [%s] is eligible for upgrade on host [%s]", plane, containerName, hostname)
		return true, nil
	}
	log.Debugf("[%s] Container [%s] is not eligible for upgrade on host [%s]", plane, containerName, hostname)
	return false, nil
}

func ReadFileFromContainer(ctx context.Context, dClient *client.Client, hostname, container, filePath string) (string, error) {
	reader, _, err := dClient.CopyFromContainer(ctx, container, filePath)
	if err != nil {
		return "", fmt.Errorf("Failed to copy file [%s] from container [%s] on host [%s]: %v", filePath, container, hostname, err)
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)
	if _, err := tarReader.Next(); err != nil {
		return "", err
	}
	file, err := ioutil.ReadAll(tarReader)
	if err != nil {
		return "", err
	}
	return string(file), nil
}

func ReadContainerLogs(ctx context.Context, dClient *client.Client, containerName string) (io.ReadCloser, error) {
	return dClient.ContainerLogs(ctx, containerName, types.ContainerLogsOptions{ShowStdout: true})
}

func sliceEqualsIgnoreOrder(left, right []string) bool {
	return sets.NewString(left...).Equal(sets.NewString(right...))
}

func tryRegistryAuth(pr ytypes.PrivateRegistry) types.RequestPrivilegeFunc {
	return func() (string, error) {
		return getRegistryAuth(pr)
	}
}

func getRegistryAuth(pr ytypes.PrivateRegistry) (string, error) {
	authConfig := types.AuthConfig{
		Username: pr.User,
		Password: pr.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encodedJSON), nil
}

func GetImageRegistryConfig(image string, prsMap map[string]ytypes.PrivateRegistry) (string, string, error) {
	namedImage, err := ref.ParseNormalizedNamed(image)
	if err != nil {
		return "", "", err
	}
	regURL := ref.Domain(namedImage)
	if pr, ok := prsMap[regURL]; ok {
		// We do this if we have some login information
		regAuth, err := getRegistryAuth(pr)
		return regAuth, pr.URL, err
	}
	return "", "", nil
}
