package dhcp

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libkv/store"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/types"
)

const (
	dhcpPrefix    = "dhcp"                          // prefix used for persistent driver storage
	defaultPrefix = "/var/lib/docker/network/files" // location of datastore
)

type ipv4Subnet struct {
	SubnetIP string
	GwIP     string
}

type ipv6Subnet struct {
	SubnetIP string
	GwIP     string
}

// makeDhcpDsConfig returns the basic parameters for the drivers persistent datastore
func makeDhcpDsConfig() *discoverapi.DatastoreConfigData {
	dsConfig := &discoverapi.DatastoreConfigData{
		Scope:    "local",
		Provider: "boltdb",
		Address:  defaultPrefix + "/local-kv.db",
		Config: &store.Config{
			Bucket: "libnetwork",
		},
	}

	return dsConfig
}

// initStore initialize the drivers persistent datastore
func (d *allocator) initStore() error {

	dsConfig := makeDhcpDsConfig()
	var err error
	d.store, err = datastore.NewDataStoreFromConfig(*dsConfig)
	if err != nil {
		logrus.Errorf("DHCP driver failed to initialize data store: %v", err)
	}

	// retrieve persistent pools from cache
	return d.populateDhcpPools()
}

// populateDhcpPools is invoked at driver init to recreate persistently stored DHCP Pools
func (d *allocator) populateDhcpPools() error {
	kvol, err := d.store.List(datastore.Key(dhcpPrefix), &dhcpPool{})
	if err != nil && err != datastore.ErrKeyNotFound {
		return fmt.Errorf("failed to get dhcp configurations from store: %v", err)
	}
	// If empty it simply means no dhcp networks have been created yet
	if err == datastore.ErrKeyNotFound {
		return nil
	}
	for _, kvo := range kvol {
		config := kvo.(*dhcpPool)
		// initialize the lease table for new leases
		config.dhcpLeases = dhcpLeaseTable{}
		d.addPool(config)
	}

	return nil
}

// storeUpdate used to update persistent dhcp records as they are created
func (d *allocator) storeUpdate(kvObject datastore.KVObject) error {
	if d.store == nil {
		logrus.Warnf("dhcp store not initialized. kv object %s is not added to the store", datastore.Key(kvObject.Key()...))
		return nil
	}
	if err := d.store.PutObjectAtomic(kvObject); err != nil {
		return fmt.Errorf("failed to update dhcp store for object type %T: %v", kvObject, err)
	}

	return nil
}

// storeDelete used to delete dhcp network records from persistent cache as they are deleted
func (d *allocator) storeDelete(kvObject datastore.KVObject) error {
	if d.store == nil {
		logrus.Debugf("dhcp store not initialized. kv object %s is not deleted from store", datastore.Key(kvObject.Key()...))
		return nil
	}
retry:
	if err := d.store.DeleteObjectAtomic(kvObject); err != nil {
		if err == datastore.ErrKeyModified {
			if err := d.store.GetObject(datastore.Key(kvObject.Key()...), kvObject); err != nil {
				return fmt.Errorf("could not update the kvobject to latest when trying to delete: %v", err)
			}
			goto retry
		}
		return err
	}

	return nil
}

func (config *dhcpPool) MarshalJSON() ([]byte, error) {
	nMap := make(map[string]interface{})
	nMap["ID"] = config.ID
	nMap["CreatedSlaveLink"] = config.CreatedSlaveLink
	nMap["DhcpInterface"] = config.DhcpInterface
	nMap["DhcpServer"] = config.DhcpServer.String()
	if config.Gateway != nil {
		nMap["Gateway"] = config.Gateway.String()
	}
	if config.IPv4Subnet != nil {
		nMap["IPv4Subnet"] = config.IPv4Subnet.String()
	}

	return json.Marshal(nMap)
}

func (config *dhcpPool) UnmarshalJSON(b []byte) error {
	var (
		err  error
		nMap map[string]interface{}
	)
	if err = json.Unmarshal(b, &nMap); err != nil {
		return err
	}
	config.ID = nMap["ID"].(string)
	config.CreatedSlaveLink = nMap["CreatedSlaveLink"].(bool)
	config.DhcpInterface = nMap["DhcpInterface"].(string)
	config.DhcpServer = net.ParseIP(nMap["DhcpServer"].(string))
	// handle scenarios where the gateway is not user defined and thus null
	if config.Gateway != nil {
		if config.Gateway, err = types.ParseCIDR(nMap["Gateway"].(string)); err != nil {
			return fmt.Errorf("failed to decode DHCP pool IPv4 gateway address after json unmarshal: %s", nMap["Gateway"].(string))
		}
	}
	if config.IPv4Subnet, err = types.ParseCIDR(nMap["IPv4Subnet"].(string)); err != nil {
		return fmt.Errorf("failed to decode DHCP pool IPv4 network address after json unmarshal: %s", nMap["IPv4Subnet"].(string))
	}

	return nil
}

func (config *dhcpPool) Key() []string {
	return []string{dhcpPrefix, config.ID}
}

func (config *dhcpPool) KeyPrefix() []string {
	return []string{dhcpPrefix}
}

func (config *dhcpPool) Value() []byte {
	b, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	return b
}

func (config *dhcpPool) SetValue(value []byte) error {
	return json.Unmarshal(value, config)
}

func (config *dhcpPool) Index() uint64 {
	return config.dbIndex
}

func (config *dhcpPool) SetIndex(index uint64) {
	config.dbIndex = index
	config.dbExists = true
}

func (config *dhcpPool) Exists() bool {
	return config.dbExists
}

func (config *dhcpPool) Skip() bool {
	return false
}

func (config *dhcpPool) New() datastore.KVObject {
	return &dhcpPool{}
}

func (config *dhcpPool) CopyTo(o datastore.KVObject) error {
	dstCfg := o.(*dhcpPool)
	*dstCfg = *config

	return nil
}

func (config *dhcpPool) DataScope() string {
	return datastore.LocalScope
}
