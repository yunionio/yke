package tunnel

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"yunion.io/yunioncloud/pkg/log"
)

const (
	DockerDialerTimeout = 30
)

type dialFunc func(network, address string) (net.Conn, error)

type HostConfig struct {
	Address         string
	Port            string
	Username        string
	SSHKeyString    string
	SSHKeyPath      string
	SSHPassphrase   []byte
	UseSSHAgentAuth bool
	DockerSocket    string
}

type DialerFactory func(h HostConfig) (dialFunc, error)

type dialer struct {
	signer          ssh.Signer
	sshKeyString    string
	sshAddress      string
	sshPassphrase   []byte
	username        string
	netConn         string
	dockerSocket    string
	useSSHAgentAuth bool
}

func newDialer(h HostConfig, kind string) (*dialer, error) {
	var err error
	d := &dialer{
		sshAddress:      fmt.Sprintf("%s:%s", h.Address, h.Port),
		username:        h.Username,
		dockerSocket:    h.DockerSocket,
		sshKeyString:    h.SSHKeyString,
		netConn:         "unix",
		sshPassphrase:   h.SSHPassphrase,
		useSSHAgentAuth: h.UseSSHAgentAuth,
	}

	if d.sshKeyString == "" {
		d.sshKeyString, err = PrivateKeyPath(h.SSHKeyPath)
		if err != nil {
			return nil, err
		}
	}

	switch kind {
	case "network", "health":
		d.netConn = "tcp"
	}

	if len(d.dockerSocket) == 0 {
		d.dockerSocket = "/var/run/docker.sock"
	}

	log.Debugf("Dialer config: %#v", d)

	return d, nil
}

func (d *dialer) getSSHTunnelConnection() (*ssh.Client, error) {
	cfg, err := getSSHConfig(d.username, d.sshKeyString, d.sshPassphrase, d.useSSHAgentAuth)
	if err != nil {
		return nil, fmt.Errorf("Error configuring SSH: %v", err)
	}

	// Establish connection with SSH Server
	return ssh.Dial("tcp", d.sshAddress, cfg)
}

func (d *dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.getSSHTunnelConnection()
	if err != nil {
		return nil, fmt.Errorf("Failed to dial ssh using address [%s]: %v", d.sshAddress, err)
	}

	// Docker socket
	if d.netConn == "unix" {
		addr = d.dockerSocket
		network = d.netConn
	}

	remote, err := conn.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial to %s: %v", addr, err)
	}
	return remote, err
}

func (d *dialer) DialDocker(network, addr string) (net.Conn, error) {
	return d.Dial(network, addr)
}

func (d *dialer) DialLocalConn(network, addr string) (net.Conn, error) {
	return d.Dial(network, addr)
}

func SSHFactory(h HostConfig) (dialFunc, error) {
	d, err := newDialer(h, "docker")
	return d.Dial, err
}

func LocalConnFactory(h HostConfig) (dialFunc, error) {
	d, err := newDialer(h, "network")
	return d.Dial, err
}

func NewHTTPClient(h HostConfig, dialerFactory DialerFactory) (*http.Client, error) {
	factory := dialerFactory
	if factory == nil {
		factory = SSHFactory
	}
	dialer, err := factory(h)
	if err != nil {
		return nil, err
	}
	dockerDialerTimeout := time.Second * DockerDialerTimeout
	return &http.Client{
		Transport: &http.Transport{
			Dial:                  dialer,
			TLSHandshakeTimeout:   dockerDialerTimeout,
			IdleConnTimeout:       dockerDialerTimeout,
			ResponseHeaderTimeout: dockerDialerTimeout,
		},
	}, nil
}
