// Command omada-clients lists Omada connected clients grouped by network,
// to help pick probe candidates and debug VLAN mapping.
//
// Credentials come from the OMADA_HOST, OMADA_CLIENT_ID, and OMADA_CLIENT_SECRET
// environment variables (optionally OMADA_SITE to target a specific site).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	omada "github.com/jpvelasco/nyx/internal/backends/omada"
)

func main() {
	os.Exit(runMain(os.Getenv, os.Stdout, os.Stderr))
}

// runMain is the main entrypoint body, factored out so tests can exercise
// the exit-code path without calling os.Exit.
func runMain(getenv func(string) string, stdout, stderr io.Writer) int {
	if err := run(getenv, stdout); err != nil {
		fmt.Fprintln(stderr, "omada-clients:", err)
		return 1
	}
	return 0
}

// run executes the omada-clients workflow. It takes env lookup and an output
// writer as parameters so tests can inject fakes.
func run(getenv func(string) string, stdout io.Writer) error {
	host := getenv("OMADA_HOST")
	clientID := getenv("OMADA_CLIENT_ID")
	clientSecret := getenv("OMADA_CLIENT_SECRET")
	if host == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("set OMADA_HOST, OMADA_CLIENT_ID, and OMADA_CLIENT_SECRET")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := omada.NewClient(ctx, host, true, "")
	if err != nil {
		return err
	}
	if err := client.Login(ctx, clientID, clientSecret); err != nil {
		return err
	}
	defer client.Logout(ctx) //nolint:errcheck

	sites, err := client.GetSites(ctx)
	if err != nil {
		return err
	}
	site, err := omada.SelectSite(sites, getenv("OMADA_SITE"))
	if err != nil {
		return err
	}

	siteID := site.EffectiveID()
	clients, err := client.GetClients(ctx, siteID)
	if err != nil {
		return err
	}
	// The thin wire has no IP or network name; the DHCP user list is
	// required for the grouped output, so failures propagate.
	nets, err := client.GetNetworks(ctx, siteID)
	if err != nil {
		return err
	}
	if err := client.EnrichFromDHCP(ctx, siteID, clients, nets); err != nil {
		return err
	}

	fmt.Fprint(stdout, omada.RenderClientInventory(site.Name, clients))
	return nil
}
