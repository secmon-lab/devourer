package interfaces

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/secmon-lab/devourer/pkg/domain/model"
)

type Capture interface {
	Read() chan gopacket.Packet
}

type Dumper interface {
	Dump(ctx context.Context, record *model.Record) error
	Close()
}

type Repository interface {
	// SaveAddrName saves a mapping from IP address to domain name (from DNS)
	SaveAddrName(ctx context.Context, addr net.IP, name string) error
	// SaveHWAddrName saves a mapping from MAC address to hostname (from mDNS/LLMNR/NBNS/DHCP)
	SaveHWAddrName(ctx context.Context, hwAddr net.HardwareAddr, name string) error

	// LookupByAddr returns names associated with an IP address
	LookupByAddr(ctx context.Context, addr net.IP) ([]string, error)
	// LookupByHWAddr returns names associated with a MAC address
	LookupByHWAddr(ctx context.Context, hwAddr net.HardwareAddr) ([]string, error)
}
