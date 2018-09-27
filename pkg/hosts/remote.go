package hosts

import (
	"fmt"

	"github.com/cosiner/socker"
)

func (h *Host) SSH() (*socker.SSH, error) {
	var pkey string = h.SSHKey
	var err error
	if len(pkey) == 0 {
		pkey, err = privateKeyPath(h.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("Get PrivateKey: %v", err)
		}
	}
	config := &socker.Auth{User: h.User, PrivateKey: pkey}
	addr := fmt.Sprintf("%s:%s", h.Address, h.Port)
	gate, err := socker.Dial(addr, config)
	if err != nil {
		return nil, fmt.Errorf("Dial %s use private key %#v: %v", addr, config, err)
	}
	return gate, nil
}

func (h *Host) Rcmd(cmd string, env ...string) (string, error) {
	a, err := h.SSH()
	if err != nil {
		return "", err
	}
	ret, err := a.Rcmd(cmd, env...)
	return string(ret), err
}
