package spoof

// ProbeResult is the outcome of testing one outer spoof protocol between two servers.
type ProbeProtoResult struct {
	Proto string `json:"proto"`
	Title string `json:"title"`
	OutOK bool   `json:"out_ok"` // forged packets from this server reached the peer
	InOK  bool   `json:"in_ok"`  // forged packets from the peer reached this server
}

// ProbeReport summarizes a bidirectional Spoof path test across all outer protocols.
type ProbeReport struct {
	Peer             string             `json:"peer"`
	Remote           string             `json:"remote"`
	SpoofSrc         string             `json:"spoof_src"`
	Port             uint16             `json:"port"`
	OutEmitOK        bool               `json:"out_emit_ok"` // this server's kernel/NIC allowed emitting forged packets
	InEmitOK         bool               `json:"in_emit_ok"`  // peer's kernel/NIC allowed emitting forged packets
	Protos           []ProbeProtoResult `json:"protos"`
	RecommendedProto string             `json:"recommended_proto,omitempty"`
	RecommendedDir   string             `json:"recommended_dir,omitempty"` // "both", "out", "in", or ""
	Summary          string             `json:"summary"`
}

// ProtoTitle returns a human-readable label for a spoof outer protocol.
func ProtoTitle(p string) string {
	switch NormalizeProto(p) {
	case ProtoUDP:
		return "UDP (پیشنهادی)"
	case ProtoTCP:
		return "FakeTCP / TCP خام"
	case ProtoGRE:
		return "GRE (پروتکل 47)"
	case ProtoIPIP:
		return "IPIP (پروتکل 4)"
	case ProtoSIT:
		return "6to4 / SIT (پروتکل 41)"
	case ProtoICMP:
		return "ICMP (پینگ)"
	default:
		return p
	}
}
