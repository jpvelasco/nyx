// Command omada-clients lists Omada connected clients grouped by network,
// to help pick probe candidates and debug VLAN mapping.
//
// Credentials come from the OMADA_HOST, OMADA_USERNAME, and OMADA_PASSWORD
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
	os.Exit(execute(os.Getenv, os.Stdout, os.Stderr))
}

// execute runs the omada-clients workflow and returns an exit code.
// It returns 0 on success, 1 on failure.
func execute(getenv func(string) string, stdout, stderr io.Writer) int {
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
	user := getenv("OMADA_USERNAME")
	pass := getenv("OMADA_PASSWORD")
	if host == "" || user == "" || pass == "" {
		return fmt.Errorf("set OMADA_HOST, OMADA_USERNAME, and OMADA_PASSWORD")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := omada.NewClient(ctx, host, true, "")
	if err != nil {
		return err
	}
	if err := client.Login(ctx, user, pass); err != nil {
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

	clients, err := client.GetClients(ctx, site.EffectiveID())
	if err != nil {
		return err
	}

	fmt.Fprint(stdout, omada.RenderClientInventory(site.Name, clients))
	return nil
}
