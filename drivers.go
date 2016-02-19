package libnetwork

import (
	"strings"

	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"

	builtinIpam "github.com/docker/libnetwork/ipams/builtin"
	remoteIpam "github.com/docker/libnetwork/ipams/remote"
)

type initializer struct {
	fn    func(driverapi.DriverCallback, map[string]interface{}) error
	ntype string
}

func initDrivers(c *controller) error {
	for _, i := range getInitializers() {
		if err := i.fn(c, makeDriverConfig(c, i.ntype)); err != nil {
			return err
		}
	}

	return nil
}

func insertDatastoreConfig(scopes map[string]*datastore.ScopeCfg, config map[string]interface{}) {
	for k, v := range scopes {
		if !v.IsValid() {
			continue
		}

		config[netlabel.MakeKVClient(k)] = discoverapi.DatastoreConfigData{
			Scope:    k,
			Provider: v.Client.Provider,
			Address:  v.Client.Address,
			Config:   v.Client.Config,
		}
	}
}

func makeDriverConfig(c *controller, ntype string) map[string]interface{} {
	if c.cfg == nil {
		return nil
	}

	config := make(map[string]interface{})

	for _, label := range c.cfg.Daemon.Labels {
		if !strings.HasPrefix(netlabel.Key(label), netlabel.DriverPrefix+"."+ntype) {
			continue
		}

		config[netlabel.Key(label)] = netlabel.Value(label)
	}

	drvCfg, ok := c.cfg.Daemon.DriverCfg[ntype]
	if ok {
		for k, v := range drvCfg.(map[string]interface{}) {
			config[k] = v
		}
	}

	// We don't send datastore configs to external plugins
	if ntype == "remote" {
		return config
	}

	insertDatastoreConfig(c.cfg.Scopes, config)

	return config
}

func initIpams(ic ipamapi.Callback) error {
	config := make(map[string]interface{})
	insertDatastoreConfig(ic.(*controller).cfg.Scopes, config)
	for _, fn := range [](func(ipamapi.Callback, map[string]interface{}) error){
		builtinIpam.Init,
		remoteIpam.Init,
	} {
		if err := fn(ic, config); err != nil {
			return err
		}
	}
	return nil
}
