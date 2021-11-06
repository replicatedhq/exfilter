package exfilter

import (
	"github.com/exfilter/exfilter/pkg/probe"
	"github.com/spf13/cobra"
)

func Run() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "run",
		Short:         "",
		Long:          ``,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO detect if root

			if err := probe.Start(); err != nil {
				return err
			}

			return nil
		},
	}

	return cmd
}
