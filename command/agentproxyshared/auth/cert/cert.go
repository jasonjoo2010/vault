// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cert

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agentproxyshared/auth"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
)

type certMethod struct {
	logger    hclog.Logger
	mountPath string
	name      string

	caCert     string
	clientCert string
	clientKey  string
	reload     bool

	// Client is the cached client to use if cert info was provided.
	client *api.Client

	stopCh          chan struct{}
	doneCh          chan struct{}
	credSuccessGate chan struct{}
	ticker          *time.Ticker
	once            *sync.Once
	credsFound      chan struct{}
	latestHash      *string
}

var _ auth.AuthMethodWithClient = &certMethod{}

func NewCertAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}

	// Not concerned if the conf.Config is empty as the 'name'
	// parameter is optional when using TLS Auth
	lastHash := ""
	c := &certMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,

		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		credSuccessGate: make(chan struct{}),
		once:            new(sync.Once),
		credsFound:      make(chan struct{}),
		latestHash:      &lastHash,
	}

	if conf.Config != nil {
		nameRaw, ok := conf.Config["name"]
		if !ok {
			nameRaw = ""
		}
		c.name, ok = nameRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'name' config value to string")
		}

		caCertRaw, ok := conf.Config["ca_cert"]
		if ok {
			c.caCert, ok = caCertRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'ca_cert' config value to string")
			}
		}

		clientCertRaw, ok := conf.Config["client_cert"]
		if ok {
			c.clientCert, ok = clientCertRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cert_file' config value to string")
			}
		}

		clientKeyRaw, ok := conf.Config["client_key"]
		if ok {
			c.clientKey, ok = clientKeyRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cert_key' config value to string")
			}
		}

		reload, ok := conf.Config["reload"]
		if ok {
			c.reload, ok = reload.(bool)
			if !ok {
				return nil, errors.New("could not convert 'reload' config value to bool")
			}
		}
	}

	if c.reload {
		readPeriod := 1 * time.Minute
		if jwtReadPeriodRaw, ok := conf.Config["reload_period"]; ok {
			jwtReadPeriod, err := parseutil.ParseDurationSecond(jwtReadPeriodRaw)
			if err != nil {
				return nil, fmt.Errorf("error parsing 'jwt_read_period' value: %w", err)
			}
			readPeriod = jwtReadPeriod
		}
		c.ticker = time.NewTicker(readPeriod)

		go c.runWatcher()
	}

	return c, nil
}

func (c *certMethod) Authenticate(_ context.Context, client *api.Client) (string, http.Header, map[string]interface{}, error) {
	c.logger.Trace("beginning authentication")

	authMap := map[string]interface{}{}

	if c.name != "" {
		authMap["name"] = c.name
	}

	return fmt.Sprintf("%s/login", c.mountPath), nil, authMap, nil
}

func (c *certMethod) NewCreds() chan struct{} {
	return c.credsFound
}

func (c *certMethod) CredSuccess() {
	c.once.Do(func() {
		close(c.credSuccessGate)
	})
}

func (c *certMethod) Shutdown() {
	if c.reload {
		c.ticker.Stop()
		close(c.stopCh)
		<-c.doneCh
	}
}

// AuthClient uses the existing client's address and returns a new client with
// the auto-auth method's certificate information if that's provided in its
// config map.
func (c *certMethod) AuthClient(client *api.Client) (*api.Client, error) {
	c.logger.Trace("deriving auth client to use")

	clientToAuth := client

	if c.caCert != "" || (c.clientKey != "" && c.clientCert != "") {
		// Return cached client if present
		if c.client != nil && !c.reload {
			return c.client, nil
		}

		config := api.DefaultConfig()
		if config.Error != nil {
			return nil, config.Error
		}
		config.Address = client.Address()

		t := &api.TLSConfig{
			CACert:     c.caCert,
			ClientCert: c.clientCert,
			ClientKey:  c.clientKey,
		}

		// Setup TLS config
		if err := config.ConfigureTLS(t); err != nil {
			return nil, err
		}

		// set last hash if load it successfully
		if hash, err := c.hashCert(c.clientCert, c.clientKey, c.caCert); err != nil {
			return nil, err
		} else {
			c.latestHash = &hash
		}

		var err error
		clientToAuth, err = api.NewClient(config)
		if err != nil {
			return nil, err
		}
		if ns := client.Headers().Get(consts.NamespaceHeaderName); ns != "" {
			clientToAuth.SetNamespace(ns)
		}

		// Cache the client for future use
		c.client = clientToAuth
	}

	return clientToAuth, nil
}

func (c *certMethod) hashCert(certFile, keyFile, caFile string) (string, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	c.logger.Debug("Loaded cert file", "file", certFile, "length", len(certPEMBlock))
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	c.logger.Debug("Loaded key file", "file", keyFile, "length", len(keyPEMBlock))
	caPEMBlock, err := os.ReadFile(caFile)
	if err != nil {
		return "", err
	}
	c.logger.Debug("Loaded ca file", "file", caFile, "length", len(caPEMBlock))

	// verify
	_, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return "", err
	}
	c.logger.Debug("The cert/key are valid")

	sum := sha1.Sum(append(append(certPEMBlock, keyPEMBlock...), caPEMBlock...))
	return hex.EncodeToString(sum[:]), nil
}

func (c *certMethod) runWatcher() {
	defer close(c.doneCh)

	select {
	case <-c.stopCh:
		return

	case <-c.credSuccessGate:
		// We only start the next loop once we're initially successful,
		// since at startup Authenticate will be called, and we don't want
		// to end up immediately re-authenticating by having found a new
		// value
	}

	for {
		changed := false
		select {
		case <-c.stopCh:
			return

		case <-c.ticker.C:
			c.logger.Debug("Checking if files changed", "cert", c.clientCert, "key", c.clientKey)
			hash, err := c.hashCert(c.clientCert, c.clientKey, c.caCert)
			// ignore errors in watcher
			if err == nil {
				c.logger.Debug("hash before/after", "new", hash, "old", *c.latestHash)
				changed = *c.latestHash != hash
			} else {
				c.logger.Warn("hash failed for cert/key files", "err", err)
			}
		}

		if changed {
			c.logger.Info("The cert/key files changed")
			select {
			case c.credsFound <- struct{}{}:
			case <-c.stopCh:
			}
		}
	}
}
