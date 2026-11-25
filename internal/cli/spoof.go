package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"hltunnel/internal/identity"
	"hltunnel/internal/manage"
)

func spoofTestCmd() *cobra.Command {
	var src string
	cmd := &cobra.Command{
		Use:   "spoof-test <peer>",
		Short: "Test forged-source-IP (Spoof) connectivity across all outer protocols (UDP, FakeTCP, GRE, IPIP, SIT, ICMP)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			id, err := identity.LoadOrCreate()
			if err != nil {
				return err
			}
			ctx, cancel := ctxTimeout(20 * time.Second)
			defer cancel()
			title(fmt.Sprintf("Spoof path test → %s", args[0]))
			rep, err := manage.TestSpoof(ctx, id, args[0], src)
			if err != nil {
				return err
			}
			fmt.Printf("  %-22s %-18s %-18s\n", dim("OUTER PROTOCOL"), dim("THIS → "+rep.Peer), dim(rep.Peer+" → THIS"))
			for _, p := range rep.Protos {
				outStr := badText("blocked")
				if p.OutOK {
					outStr = okText("PASS")
				}
				inStr := badText("blocked")
				if p.InOK {
					inStr = okText("PASS")
				}
				fmt.Printf("  %-22s %-27s %-27s\n", bold(strings.ToUpper(p.Proto))+" ("+p.Title+")", outStr, inStr)
			}
			fmt.Println()
			info("%s", rep.Summary)
			if rep.RecommendedProto != "" {
				fmt.Println()
				info("run any protocol over Spoof: sudo hltunnel quick %s --mode 6to4 --spoof --spoof-proto %s --spoof-mode %s",
					rep.Peer, rep.RecommendedProto, rep.RecommendedDir)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&src, "src", "auto", "spoof source IP mode: auto, iran, rotate, or an IPv4 address")
	return cmd
}

func okText(s string) string  { return green("✓ " + s) }
func badText(s string) string { return red("✗ " + s) }
