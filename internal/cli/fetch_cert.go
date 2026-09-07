package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/jpvelasco/nyx/internal/tlsutil"
	"github.com/spf13/cobra"
)

var (
	fetchCertHost  string
	fetchCertOut   string
	fetchCertForce bool
)

// buildFetchCertCmd is the extra (non-capability) helper that writes the
// controller's presented certificate chain to a PEM so the operator can
// pin it with --ca-cert. It is not advertised via Capabilities().
func buildFetchCertCmd(providerName string) *cobra.Command {
	hostEnv := "OMADA_HOST"
	if strings.EqualFold(providerName, "opnsense") {
		hostEnv = "OPNSENSE_HOST"
	}
	cmd := &cobra.Command{
		Use:   "fetch-cert",
		Short: "Write the controller's TLS certificate chain to a PEM for --ca-cert pinning",
		RunE: func(_ *cobra.Command, _ []string) error {
			host := strings.TrimSpace(fetchCertHost)
			if host == "" {
				host = strings.TrimSpace(os.Getenv(hostEnv))
			}
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			n, err := tlsutil.FetchAndWrite(tlsutil.FetchOptions{
				Host:    host,
				Out:     fetchCertOut,
				Timeout: dur,
				Force:   fetchCertForce,
			})
			if err != nil {
				return err
			}
			fmt.Printf("wrote %s (%d certs)\n", fetchCertOut, n)
			return nil
		},
	}
	cmd.Flags().StringVar(&fetchCertHost, "host", "", "Controller IP or hostname")
	cmd.Flags().StringVar(&fetchCertOut, "out", "", "Path to write the PEM (required)")
	cmd.Flags().BoolVar(&fetchCertForce, "force", false, "Overwrite an existing --out file")
	return cmd
}
