package repo

import (
	"context"
	"net"
	"sync"

	"github.com/secmon-lab/devourer/pkg/domain/interfaces"
)

type Memory struct {
	addrNames   map[string]map[string]struct{}
	hwAddrNames map[string]map[string]struct{}
	mu          sync.RWMutex
}

var _ interfaces.Repository = (*Memory)(nil)

func NewMemory() *Memory {
	return &Memory{
		addrNames:   make(map[string]map[string]struct{}),
		hwAddrNames: make(map[string]map[string]struct{}),
	}
}

func (m *Memory) SaveAddrName(_ context.Context, addr net.IP, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := addr.String()
	if m.addrNames[key] == nil {
		m.addrNames[key] = make(map[string]struct{})
	}
	m.addrNames[key][name] = struct{}{}
	return nil
}

func (m *Memory) SaveHWAddrName(_ context.Context, hwAddr net.HardwareAddr, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := hwAddr.String()
	if m.hwAddrNames[key] == nil {
		m.hwAddrNames[key] = make(map[string]struct{})
	}
	m.hwAddrNames[key][name] = struct{}{}
	return nil
}

func (m *Memory) LookupByAddr(_ context.Context, addr net.IP) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := m.addrNames[addr.String()]
	if len(names) == 0 {
		return nil, nil
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	return result, nil
}

func (m *Memory) LookupByHWAddr(_ context.Context, hwAddr net.HardwareAddr) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := m.hwAddrNames[hwAddr.String()]
	if len(names) == 0 {
		return nil, nil
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	return result, nil
}
