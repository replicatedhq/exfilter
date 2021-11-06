package exfilter

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/exfilter/exfilter/pkg/version"
)

func Version() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "version",
		Short:         "exfilter version information",
		Long:          `Prints the current version of the Exfilter CLI. This may or may not match the version in the cluster.`,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Exfilter %s\n", version.Version())
			return nil
		},
	}

	return cmd
}
