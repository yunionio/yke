package tunnel

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"yunion.io/yunioncloud/pkg/log"
)

func PrivateKeyPath(sshKeyPath string) (string, error) {
	if sshKeyPath[:2] == "~/" {
		sshKeyPath = filepath.Join(os.Getenv("HOME"), sshKeyPath[2:])
	}
	buff, err := ioutil.ReadFile(sshKeyPath)
	if err != nil {
		return "", err
	}
	return string(buff), nil
}

func parsePrivateKey(keyBuff string) (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(keyBuff))
}

func parsePrivateKeyWithPassphrase(keyBuff string, passphrase []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKeyWithPassphrase([]byte(keyBuff), passphrase)
}

func getPrivateKeySigner(privateKeyString string, passphrase []byte) (ssh.Signer, error) {
	key, err := parsePrivateKey(privateKeyString)
	if err != nil && strings.Contains(err.Error(), "decode encrypted private keys") {
		key, err = parsePrivateKeyWithPassphrase(privateKeyString, passphrase)
	}
	return key, err
}

func getSSHConfig(username, privateKeyString string, passphrase []byte, useAgentAuth bool) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Kind of a double check now.
	if useAgentAuth {
		if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); sshAgentSock != "" {
			sshAgent, err := net.Dial("unix", sshAgentSock)
			if err != nil {
				return config, fmt.Errorf("Cannot connect to SSH Auth socket %q: %v", sshAgentSock, err)
			}

			config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
			log.Debugf("using %q SSH_AUTH_SOCK", sshAgentSock)
			return config, nil
		}
	}

	signer, err := getPrivateKeySigner(privateKeyString, passphrase)
	if err != nil {
		return config, err
	}
	config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	return config, nil
}
