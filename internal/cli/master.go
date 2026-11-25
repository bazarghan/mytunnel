package cli

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"hltunnel/internal/config"
	"hltunnel/internal/manage"
)

// The servers that manage this one, from this side: for cleaning up after
// one that is gone and can't do it itself.

func masterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "master", Short: "The main servers that manage this one: list, forget, keep"}
	cmd.AddCommand(masterListCmd(), masterForgetCmd(), masterKeepCmd(), masterAutoForgetCmd())
	return cmd
}

func masterListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the main servers, when each last reached this one, and their tunnels",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadNode()
			if err != nil {
				return err
			}
			printMasters(st)
			return nil
		},
	}
}

func printMasters(st *config.State) {
	title("Main servers")
	ms := manage.Masters(st, time.Now())
	if len(ms) == 0 {
		info("none: no other server manages this one")
		return
	}
	for _, m := range ms {
		seen := dim("not seen yet")
		if m.LastContact > 0 {
			seen = dim("seen " + time.Unix(m.LastContact, 0).Local().Format("2006-01-02 15:04"))
			if m.SilentDays >= config.WarnSilentDays {
				seen = yellow(fmt.Sprintf("silent %d days", m.SilentDays))
			}
		}
		forget := ""
		switch {
		case m.Keep:
			forget = dim(" · kept")
		case m.ForgetIn >= 0 && m.SilentDays >= config.WarnSilentDays:
			forget = yellow(fmt.Sprintf(" · forgotten in %d days", m.ForgetIn))
		}
		dropped := ""
		if len(m.Dropped) > 0 {
			dropped = dim(fmt.Sprintf(" · %d removed here by hand", len(m.Dropped)))
		}
		fmt.Printf("  %-16s %-22s %d tunnels  %s%s%s\n", bold(m.Name), m.Address, m.Tunnels, seen, forget, dropped)
	}
	if d := st.ForgetDays(); d > 0 {
		info("a main server silent for %d days is forgotten with its tunnels (change: hltunnel master auto-forget <days|off>)", d)
	} else {
		info("silent main servers are never forgotten (change: hltunnel master auto-forget <days>)")
	}
}

func masterForgetCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "forget <name|address|all>",
		Short: "Forget a main server here, removing every tunnel and forward it set up",
		Long: "Forgets a main server on this server and removes the tunnels, forwards\n" +
			"and IPsec it set up here; the other main servers keep theirs. For a\n" +
			"server that is gone, or that removed this one while it couldn't reach\n" +
			"it. A server that still runs has to pair with this one again.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			if !yes && !confirm(red("Forget ")+bold(args[0])+" and remove its tunnels here?", false) {
				info("nothing changed")
				return nil
			}
			n, ch, err := manage.ForgetMaster(args[0])
			if err != nil {
				return err
			}
			printChange(ch)
			success("forgot %s; %d tunnels removed", args[0], n)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return cmd
}

func masterKeepCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keep <name|all> [on|off]",
		Short: "Never forget a main server for being silent (off: forget it again after the set days)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keep := len(args) == 1 || args[1] == "on"
			if len(args) == 2 && args[1] != "on" && args[1] != "off" {
				return fmt.Errorf("say on or off")
			}
			if err := manage.KeepMaster(args[0], keep); err != nil {
				return err
			}
			if keep {
				success("%s is kept however long it is silent", args[0])
			} else {
				success("%s is forgotten again once silent for the set days", args[0])
			}
			return nil
		},
	}
}

func masterAutoForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auto-forget <days|off>",
		Short: fmt.Sprintf("After how many silent days a main server is forgotten (default %d)", config.DefaultForgetMasterDays),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			days := 0
			if args[0] != "off" {
				n, err := strconv.Atoi(args[0])
				if err != nil || n < 1 {
					return fmt.Errorf("give a number of days, or off")
				}
				days = n
			}
			if err := manage.SetForgetDays(days); err != nil {
				return err
			}
			if days == 0 {
				success("silent main servers are never forgotten")
			} else {
				success("a main server silent for %d days is forgotten with its tunnels", days)
			}
			return nil
		},
	}
}
