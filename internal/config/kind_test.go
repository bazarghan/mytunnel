package config

import "testing"

func TestKindLookupAndFlags(t *testing.T) {
	seen := map[Kind]bool{}
	for _, want := range Kinds() {
		if seen[want.Kind] {
			t.Fatalf("duplicate kind %q", want.Kind)
		}
		seen[want.Kind] = true
		got, err := LookupKind(want.Kind)
		if err != nil {
			t.Fatalf("LookupKind(%q): %v", want.Kind, err)
		}
		if got.Kind != want.Kind || got.DefaultPort != want.DefaultPort {
			t.Fatalf("LookupKind(%q) = %+v", want.Kind, got)
		}
		if got.IsGRE() != LaneKinds(want.Kind) {
			t.Errorf("%q IsGRE()=%v != LaneKinds()=%v", want.Kind, got.IsGRE(), LaneKinds(want.Kind))
		}
	}
	if _, err := LookupKind("unknown-proto"); err == nil {
		t.Error("expected error for unknown kind")
	}
	if !PMTUKinds(KindGRE) || PMTUKinds(KindWireGuard) {
		t.Error("unexpected PMTUKinds result")
	}
	if !IgnoreDFKinds(KindGRE) || !IgnoreDFKinds(KindGRETAP) || IgnoreDFKinds(KindIP6GRE) {
		t.Error("unexpected IgnoreDFKinds result")
	}
}

func TestEffectivePort(t *testing.T) {
	vx, _ := LookupKind(KindVXLAN)
	if vx.EffectivePort(0) != 4789 || vx.EffectivePort(1234) != 1234 {
		t.Errorf("VXLAN EffectivePort mismatch: default=%d override=%d", vx.EffectivePort(0), vx.EffectivePort(1234))
	}
	gre, _ := LookupKind(KindGRE)
	if gre.EffectivePort(0) != 0 || gre.EffectivePort(3000) != 3000 {
		t.Errorf("GRE EffectivePort mismatch")
	}
}

func TestPacketOverheadAndEncrypt(t *testing.T) {
	gre := Tunnel{Kind: KindGRE}
	if got := gre.PacketOverhead(false, false, false); got != 28 {
		t.Errorf("keyed GRE overhead = %d, want 28", got)
	}
	if got := gre.PacketOverhead(false, true, false); got != 24 {
		t.Errorf("keyless GRE overhead = %d, want 24", got)
	}
	greEnc := Tunnel{Kind: KindGRE, Encrypt: "aes-gcm-128"}
	if got := greEnc.PacketOverhead(false, false, false); got != 28+ESPOverhead {
		t.Errorf("encrypted GRE overhead = %d, want %d", got, 28+ESPOverhead)
	}

	ob := Tunnel{Kind: KindObfs, Port: 4444, Padding: 20}
	if got := ob.PacketOverhead(false, false, false); got != ObfsOverhead+20 {
		t.Errorf("HLObfs worst-case overhead = %d, want %d", got, ObfsOverhead+20)
	}
	if got := ob.PacketOverhead(true, false, true); got != ObfsOverhead+20+10 {
		t.Errorf("HLObfs v6 avg overhead = %d, want %d", got, ObfsOverhead+20+10)
	}

	sp := Tunnel{Kind: KindSpoof, SpoofProto: "tcp", SpoofNoCrypt: true, Padding: 10}
	if got := sp.PacketOverhead(false, false, true); got != SpoofOverheadFor("tcp", true)+5 {
		t.Errorf("Spoof avg overhead = %d", got)
	}

	tcp := Tunnel{Kind: KindTCP, Port: 5000, Encrypt: "aes-gcm-256"}
	if got := tcp.PacketOverhead(false, false, false); got != TCPOverhead+TCPTagOverhead {
		t.Errorf("encrypted TCP overhead = %d", got)
	}

	if got := (Tunnel{Kind: KindWireGuard}).EffectiveEncrypt(); got != "wireguard" {
		t.Errorf("WireGuard EffectiveEncrypt = %q", got)
	}
	if got := (Tunnel{Kind: KindObfs, ObfsAES: true}).EffectiveEncrypt(); got != "aes-gcm-128" {
		t.Errorf("HLObfs AES EffectiveEncrypt = %q", got)
	}
	if got := (Tunnel{Kind: KindSpoof, SpoofNoCrypt: true}).EffectiveEncrypt(); got != "" {
		t.Errorf("NoCrypt Spoof EffectiveEncrypt = %q", got)
	}
}
