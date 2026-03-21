package model

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"time"
	"unsafe"

	"github.com/cespare/xxhash"
	"github.com/google/uuid"
)

type FlowKey uint64

type FlowBase struct {
}

func (x *Flow) Key() FlowKey {
	return CalcFlowKey(&x.Src, &x.Dst, x.Protocol)
}

type Flow struct {
	ID       uuid.UUID `bigquery:"id" json:"id"`
	Protocol string    `bigquery:"protocol" json:"protocol"`
	Src      Peer      `bigquery:"src" json:"src"`
	Dst      Peer      `bigquery:"dst" json:"dst"`

	FirstSeenAt time.Time `bigquery:"first_seen_at"`
	LastSeenAt  time.Time `bigquery:"last_seen_at" json:"last_seen_at"`

	SrcStat PeerStat `bigquery:"src_stat" json:"src_stat"`
	DstStat PeerStat `bigquery:"dst_stat" json:"dst_stat"`
	Status  string   `bigquery:"status" json:"status"`
}

func NewFlow(src, dst Peer, proto string, now time.Time, stat PeerStat) *Flow {
	return &Flow{
		ID:          uuid.New(),
		Protocol:    proto,
		Src:         src,
		Dst:         dst,
		FirstSeenAt: now,
		LastSeenAt:  now,
		Status:      "init",
		SrcStat:     stat,
	}
}

func (x *Flow) Update(src *Peer, now time.Time, stat PeerStat) {
	x.LastSeenAt = now
	if x.Src.Equal(src) {
		x.SrcStat.Add(&stat)
	} else {
		x.DstStat.Add(&stat)
		x.Status = "established"
	}
}

type PeerStat struct {
	Bytes   uint64 `bigquery:"bytes" json:"bytes"`
	Packets uint64 `bigquery:"packets" json:"packets"`
}

func (x *PeerStat) Add(y *PeerStat) {
	x.Bytes += y.Bytes
	x.Packets += y.Packets
}

type Peer struct {
	Addr   net.IP           `bigquery:"addr" json:"addr"`
	Port   uint32           `bigquery:"port" json:"port"`
	HWAddr net.HardwareAddr `bigquery:"-" json:"hw_addr,omitempty"`
	Names  []string         `bigquery:"-" json:"names,omitempty"`
}

func (x Peer) Equal(y *Peer) bool {
	return net.IP.Equal(x.Addr, y.Addr) && x.Port == y.Port
}

func (x Peer) MarshalJSON() ([]byte, error) {
	type peerJSON struct {
		Addr   net.IP   `json:"addr"`
		Port   uint32   `json:"port"`
		HWAddr string   `json:"hw_addr,omitempty"`
		Names  []string `json:"names,omitempty"`
	}
	p := peerJSON{
		Addr:  x.Addr,
		Port:  x.Port,
		Names: x.Names,
	}
	if x.HWAddr != nil {
		p.HWAddr = x.HWAddr.String()
	}
	return json.Marshal(p)
}

func (x *Peer) UnmarshalJSON(data []byte) error {
	type peerJSON struct {
		Addr   net.IP   `json:"addr"`
		Port   uint32   `json:"port"`
		HWAddr string   `json:"hw_addr,omitempty"`
		Names  []string `json:"names,omitempty"`
	}
	var p peerJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	x.Addr = p.Addr
	x.Port = p.Port
	x.Names = p.Names
	if p.HWAddr != "" {
		hw, err := net.ParseMAC(p.HWAddr)
		if err != nil {
			return err
		}
		x.HWAddr = hw
	}
	return nil
}

type Tick int64

func CalcFlowKey(p1, p2 *Peer, proto string) FlowKey {
	// combine two IP addresses and port numbers and protocol to one byte array
	var buf []byte

	ac := bytes.Compare(p1.Addr, p2.Addr)
	switch {
	case ac < 0:
		// nothing to do
	case ac > 0:
		p1, p2 = p2, p1
	default:
		if p1.Port < p2.Port {
			// nothing to do
		} else {
			p1, p2 = p2, p1
		}
	}

	buf = append(buf, []byte(proto)...)

	buf = append(buf, p1.Addr...)
	p1Port := make([]byte, unsafe.Sizeof(p1.Port)) // #nosec: CWE-242
	binary.BigEndian.PutUint32(p1Port, p1.Port)
	buf = append(buf, p1Port...)

	buf = append(buf, p2.Addr...)
	p2Port := make([]byte, unsafe.Sizeof(p2.Port)) // #nosec: CWE-242
	binary.BigEndian.PutUint32(p2Port, p2.Port)
	buf = append(buf, p2Port...)

	return FlowKey(xxhash.Sum64(buf))
}
