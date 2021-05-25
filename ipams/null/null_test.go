package null

import (
	"testing"

	_ "github.com/docker/libnetwork/testutils"
	"github.com/docker/libnetwork/types"
)

func TestPoolRequest(t *testing.T) {
	a := allocator{}

	pid, pool, _, err := a.RequestPool(defaultAS, "", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !types.CompareIPNet(defaultPool, pool) {
		t.Fatalf("Unexpected pool returned. Expected %v. Got: %v", defaultPool, pool)
	}
	if pid != defaultPoolID {
		t.Fatalf("Unexpected pool id returned. Expected: %s. Got: %s", defaultPoolID, pid)
	}

	id, _, _, err := a.RequestPool("foo", "", "", nil, false)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if id != "foo/0.0.0.0/0" {
		t.Fatal("Wrong id")
	}

	id, p, _, err := a.RequestPool(defaultAS, "192.168.0.0/16", "", nil, false)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if id != defaultAS+"/192.168.0.0/16" {
		t.Fatalf("Wrong id")
	}
	if p.String() != "192.168.0.0/16" {
		t.Fatalf("Wrong pool")
	}

	_, _, _, err = a.RequestPool(defaultAS, "", "192.168.0.0/24", nil, false)
	if err == nil {
		t.Fatal("Unexpected success")
	}

	id, p, _, err = a.RequestPool(defaultAS, "192.168.0.0/16", "192.168.0.0/24", nil, false)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if id != defaultAS+"/192.168.0.0/16" {
		t.Fatalf("Wrong id")
	}
	if p.String() != "192.168.0.0/16" {
		t.Fatalf("Wrong pool")
	}

	_, _, _, err = a.RequestPool(defaultAS, "", "", nil, true)
	if err != nil {
		t.Fatal("Unexpected error")
	}
}

func TestOtherRequests(t *testing.T) {
	a := allocator{}

	ip, _, err := a.RequestAddress(defaultPoolID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ip != nil {
		t.Fatalf("Unexpected address returned: %v", ip)
	}

	_, _, err = a.RequestAddress("anypid", nil, nil)
	if err == nil {
		t.Fatal("Unexpected success")
	}

}
