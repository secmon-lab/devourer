package repo_test

import (
	"context"
	"net"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/secmon-lab/devourer/pkg/infra/repo"
)

func TestMemoryRepository(t *testing.T) {
	ctx := context.Background()

	t.Run("SaveAddrName and LookupByAddr", func(t *testing.T) {
		m := repo.NewMemory()
		addr := net.IPv4(192, 168, 1, 1)

		gt.NoError(t, m.SaveAddrName(ctx, addr, "example.com"))
		gt.NoError(t, m.SaveAddrName(ctx, addr, "www.example.com"))
		// duplicate should not create extra entry
		gt.NoError(t, m.SaveAddrName(ctx, addr, "example.com"))

		names, err := m.LookupByAddr(ctx, addr)
		gt.NoError(t, err)
		gt.A(t, names).Length(2).Has("example.com").Has("www.example.com")
	})

	t.Run("SaveHWAddrName and LookupByHWAddr", func(t *testing.T) {
		m := repo.NewMemory()
		hwAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

		gt.NoError(t, m.SaveHWAddrName(ctx, hwAddr, "my-laptop"))
		gt.NoError(t, m.SaveHWAddrName(ctx, hwAddr, "my-laptop.local"))

		names, err := m.LookupByHWAddr(ctx, hwAddr)
		gt.NoError(t, err)
		gt.A(t, names).Length(2).Has("my-laptop").Has("my-laptop.local")
	})

	t.Run("LookupByAddr returns nil for unknown address", func(t *testing.T) {
		m := repo.NewMemory()
		names, err := m.LookupByAddr(ctx, net.IPv4(10, 0, 0, 1))
		gt.NoError(t, err)
		gt.A(t, names).Length(0)
	})

	t.Run("LookupByHWAddr returns nil for unknown address", func(t *testing.T) {
		m := repo.NewMemory()
		hwAddr, _ := net.ParseMAC("11:22:33:44:55:66")
		names, err := m.LookupByHWAddr(ctx, hwAddr)
		gt.NoError(t, err)
		gt.A(t, names).Length(0)
	})
}
