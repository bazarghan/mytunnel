package guard

import (
	"net"
	"net/netip"

	"hltunnel/internal/config"
	"hltunnel/internal/forward"
)

// Peers are the addresses let in whole: this server's peers, the far ends
// of its tunnels, and the servers that manage it.
func Peers(st *config.State) []netip.Addr {
	var out []netip.Addr
	add := func(s string) {
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	for _, p := range st.Peers {
		add(p.Address)
		add(p.Address6)
	}
	for _, t := range st.Tunnels {
		for _, sd := range t.Sides {
			if sd.Node != st.Self {
				add(sd.Endpoint)
			}
		}
	}
	for _, m := range st.Masters() {
		add(m.Master.Address)
	}
	return out
}

// Forwards are the ports this server's forwards listen on.
func Forwards(st *config.State) []Socket {
	_, fs := st.Effective()
	var out []Socket
	for _, f := range fs {
		protos := []string{"tcp", "udp"}
		switch {
		case f.Proto == "tcp" || f.Proto == "udp":
			protos = []string{f.Proto}
		case f.ModeOf() == config.ForwardRelay || f.ModeOf() == config.ForwardSocks:
			protos = []string{"tcp"}
		}
		for _, p := range forward.Expand(f.Ports) {
			for _, proto := range protos {
				out = append(out, Socket{Proto: proto, Port: uint16(p)})
			}
		}
	}
	return out
}

// Status is the guard as the panel shows it.
type Status struct {
	On        bool     `json:"on"`
	ConfirmBy int64    `json:"confirm_by,omitempty"`
	Ifaces    []string `json:"ifaces"`
	SSH       []uint16 `json:"ssh"`
	Panel     uint16   `json:"panel,omitempty"`
	Peers     int      `json:"peers"`
	Ports     []Port   `json:"ports"`
	Geo       GeoInfo  `json:"geo"`
	Dropped   uint64   `json:"dropped"`
	Error     string   `json:"error,omitempty"`
}

// Build assembles the guard's rules for st, and its status. The rules have
// no interfaces (the table is removed) while the guard is off.
func Build(st *config.State) (Input, Status) {
	g := config.Guard{}
	if st.Guard != nil {
		g = *st.Guard
	}
	ir, geo := IR()
	in := Input{SSH: SSHPorts(), ICMP: g.ICMP, Allow: g.Allow, Block: g.Block, IR: ir, Peers: Peers(st)}
	if st.Panel != nil {
		in.Panel = uint16(st.Panel.Port)
	}
	always := map[string]bool{}
	for _, p := range in.SSH {
		always[Socket{Proto: "tcp", Port: p}.Key()] = true
	}
	if in.Panel != 0 {
		always[Socket{Proto: "tcp", Port: in.Panel}.Key()] = true
	}
	in.Ports = Classify(g, Forwards(st), Sockets(), always)
	ts, _ := st.Effective()
	rawSeen := map[int]bool{}
	for _, t := range ts {
		if t.Kind != config.KindSpoof || t.Disabled {
			continue
		}
		port := t.Port
		if port == 0 {
			port = 32443
		}
		switch t.SpoofProto {
		case "", "udp":
			in.Ports = append(in.Ports, Port{Proto: "udp", Port: port, Scope: config.ScopeAll, Process: "spoof:" + t.Name})
		case "tcp":
			in.Ports = append(in.Ports, Port{Proto: "tcp", Port: port, Scope: config.ScopeAll, Process: "spoof:" + t.Name})
		case "gre":
			if !rawSeen[47] {
				rawSeen[47] = true
				in.RawProtos = append(in.RawProtos, 47)
			}
		case "ipip":
			if !rawSeen[4] {
				rawSeen[4] = true
				in.RawProtos = append(in.RawProtos, 4)
			}
		case "sit":
			if !rawSeen[41] {
				rawSeen[41] = true
				in.RawProtos = append(in.RawProtos, 41)
			}
		case "icmp":
			if !rawSeen[1] {
				rawSeen[1] = true
				in.RawProtos = append(in.RawProtos, 1)
			}
		}
	}
	ifaces := g.Ifaces
	if len(ifaces) == 0 {
		ifaces = PublicIfaces(st.Address)
	}
	stat := Status{On: g.On, ConfirmBy: g.ConfirmBy, Ifaces: ifaces, SSH: in.SSH, Panel: in.Panel, Peers: len(in.Peers), Ports: in.Ports, Geo: geo}
	if g.On {
		in.Ifaces = ifaces
		stat.Dropped, _ = Dropped()
	}
	return in, stat
}
