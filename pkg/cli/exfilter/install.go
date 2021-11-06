package exfilter

import (
	"github.com/spf13/cobra"
)

func Install() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "install",
		Short:         "Install (or upgrade) the Exfilter operator",
		Long:          ``,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	return cmd
}
