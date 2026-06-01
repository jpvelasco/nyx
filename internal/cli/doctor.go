package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/report"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check nyx environment health and validate a spec file",
	Example: `  nyx doctor
  nyx doctor --spec homelab.yaml
  nyx doctor --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var checks []models.CheckResult
		allPass := true

		// 1. nmap installed — we need it for scans
		nmapCheck := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
		if nmap.Available() {
			path, _ := exec.LookPath("nmap")
			out, err := exec.Command(path, "--version").Output()
			ver := "found"
			if err == nil && len(out) > 0 {
				line := string(out)
				if nl := len(line); nl > 60 {
					line = line[:60]
				}
				ver = line
			}
			nmapCheck.Status = models.StatusPass
			nmapCheck.Summary = fmt.Sprintf("nmap: %s", ver)
		} else {
			nmapCheck.Status = models.StatusFail
			nmapCheck.Summary = "nmap is missing — we can't scan without it"
			nmapCheck.Violations = append(nmapCheck.Violations, nmapInstallHint())
			allPass = false
		}
		nmapCheck.Finish()
		checks = append(checks, *nmapCheck)

		// 2. Platform detection
		platCheck := models.NewCheckResult("doctor", "platform", "local", runtime.GOOS)
		platCheck.Status = models.StatusPass
		platCheck.Summary = fmt.Sprintf("running on %s/%s", runtime.GOOS, runtime.GOARCH)
		platCheck.Observed["goos"] = runtime.GOOS
		platCheck.Observed["goarch"] = runtime.GOARCH
		platCheck.Finish()
		checks = append(checks, *platCheck)

		// 3. Log directory writable
		logPath := logger.DefaultPath()
		logDir := logPath[:len(logPath)-len("/nyx.log")]
		logDirCheck := models.NewCheckResult("doctor", "log_directory", "local", logDir)
		if err := os.MkdirAll(logDir, 0750); err != nil {
			logDirCheck.Status = models.StatusFail
			logDirCheck.Summary = fmt.Sprintf("can't create log directory %s: %v", logDir, err)
			allPass = false
		} else {
			testFile := logDir + "/.nyx_write_test"
			if f, err := os.Create(testFile); err != nil {
				logDirCheck.Status = models.StatusFail
				logDirCheck.Summary = fmt.Sprintf("log directory %s isn't writable: %v", logDir, err)
				allPass = false
			} else {
				f.Close()
				os.Remove(testFile)
				logDirCheck.Status = models.StatusPass
				logDirCheck.Summary = fmt.Sprintf("log directory: %s (writable)", logDir)
			}
		}
		logDirCheck.Finish()
		checks = append(checks, *logDirCheck)

		// 4. Current network environment briefing ("I just landed" experience)
		// When --spec is provided, we load it first so the briefing can match networks.
		var specForBriefing *intent.Spec
		if specFile != "" {
			spec, err := intent.LoadSpec(specFile)
			if err == nil {
				specForBriefing = spec
			}
		}
		brief := GetEnvironmentBriefing(specForBriefing)
		envCheck := models.NewCheckResult("doctor", "network_environment", "local", "current location")
		envCheck.Status = models.StatusPass
		envCheck.Summary = brief.Summary
		envCheck.Observed["interfaces"] = brief.ActiveInterfaces
		envCheck.Observed["current_ips"] = brief.CurrentIPs
		envCheck.Observed["matched_networks"] = brief.MatchedNetworks
		envCheck.Observed["multi_homed"] = brief.MultiHomed
		envCheck.Finish()
		checks = append(checks, *envCheck)

		// 5. Internet route (informational)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		routeCheck := models.NewCheckResult("doctor", "internet_route", "local", "8.8.8.8")
		if route, err := system.GetRouteToTarget(ctx, "8.8.8.8"); err != nil {
			routeCheck.Status = models.StatusWarn
			routeCheck.Summary = "no internet route detected — are you connected to a network with internet?"
		} else {
			routeCheck.Status = models.StatusPass
			routeCheck.Summary = fmt.Sprintf("internet route: via %s (dev %s)", route.Gateway, route.Device)
		}
		routeCheck.Finish()
		checks = append(checks, *routeCheck)

		// Spec checks
		if specFile != "" {
			specChecks := runSpecChecks(specFile)
			for _, sc := range specChecks {
				if sc.Status == models.StatusFail || sc.Status == models.StatusError {
					allPass = false
				}
			}
			checks = append(checks, specChecks...)
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		if jsonOutput {
			r := &models.AuditReport{
				Audit:    "doctor",
				Status:   models.ComputeOverallStatus(checks),
				Summary:  models.Tally(checks),
				Findings: checks,
			}
			return report.RenderJSON(w, r)
		}

		for _, c := range checks {
			tag := doctorTag(c.Status)
			fmt.Fprintf(w, "%s %s\n", tag, c.Summary)
			for _, v := range c.Violations {
				fmt.Fprintf(w, "       → %s\n", v)
			}
		}

		// First Contact: show the full environment briefing with detail
		if brief.Summary != "" {
			fmt.Fprintln(w, "\n"+RenderEnvironmentBriefing(brief))
		}

		if allPass {
			if specFile != "" {
				fmt.Fprintln(w, fmt.Sprintf("Everything checks out — ready to audit. Try: nyx audit --spec %s", specFile))
				fmt.Fprintln(w, "For ongoing confidence: nyx snapshot baseline then nyx drift status after future changes.")
			} else {
				fmt.Fprintln(w, "Everything checks out — nyx is ready to go.")
			}
		} else {
			fmt.Fprintln(w, "\nThere are issues above. Fix them and try again.")
			os.Exit(2)
		}
		return nil
	},
}

func runSpecChecks(path string) []models.CheckResult {
	var checks []models.CheckResult

	fileCheck := models.NewCheckResult("doctor", "spec_file", "local", path)
	data, err := os.ReadFile(path)
	if err != nil {
		fileCheck.Status = models.StatusFail
		fileCheck.Summary = fmt.Sprintf("cannot read spec file: %v", err)
		fileCheck.Violations = append(fileCheck.Violations,
			fmt.Sprintf("fix: check that %s exists and is readable", path))
		fileCheck.Finish()
		return append(checks, *fileCheck)
	}
	fileCheck.Status = models.StatusPass
	fileCheck.Summary = fmt.Sprintf("spec file readable: %s (%d bytes)", path, len(data))
	fileCheck.Finish()
	checks = append(checks, *fileCheck)

	validCheck := models.NewCheckResult("doctor", "spec_valid", "local", path)
	spec, err := intent.ParseSpec(data)
	if err != nil {
		validCheck.Status = models.StatusFail
		validCheck.Summary = fmt.Sprintf("spec validation failed: %v", err)
		validCheck.Violations = append(validCheck.Violations,
			"fix: correct the error above, then re-run nyx doctor --spec <file>")
		validCheck.Finish()
		return append(checks, *validCheck)
	}
	validCheck.Status = models.StatusPass
	validCheck.Summary = fmt.Sprintf("spec valid: version %d, site %q, %d networks, %d assertions",
		spec.Version, spec.Site, len(spec.Networks), len(spec.Assertions))
	validCheck.Finish()
	checks = append(checks, *validCheck)

	refCheck := models.NewCheckResult("doctor", "spec_references", "local", path)
	var violations []string
	for i, a := range spec.Assertions {
		if a.Type == "subnet_discovery" && spec.NetworkByName(a.Network) == nil {
			violations = append(violations, fmt.Sprintf(
				"assertion[%d]: network %q not declared — add it to the networks section", i, a.Network))
		}
		if a.Type == "vpn_route" && spec.VPNByName(a.VPN) == nil {
			violations = append(violations, fmt.Sprintf(
				"assertion[%d]: vpn %q not declared — add it to the vpn section", i, a.VPN))
		}
	}
	if len(violations) > 0 {
		refCheck.Status = models.StatusFail
		refCheck.Summary = fmt.Sprintf("%d unresolved references in spec", len(violations))
		refCheck.Violations = violations
	} else {
		refCheck.Status = models.StatusPass
		refCheck.Summary = "all assertion references resolve"
	}
	refCheck.Finish()
	checks = append(checks, *refCheck)

	// Probe reachability checks
	if len(spec.Probes) > 0 {
		for _, p := range spec.Probes {
			probeCheck := models.NewCheckResult("doctor", "probe_reachable", "local", p.Name)
			probeCheck.Expected["host"] = p.Host
			probeCheck.Expected["port"] = 22
			addr := net.JoinHostPort(p.Host, "22")
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				probeCheck.Status = models.StatusFail
				probeCheck.Summary = fmt.Sprintf("probe %q unreachable at %s:22", p.Name, p.Host)
				probeCheck.Violations = append(probeCheck.Violations,
					fmt.Sprintf("cannot connect to %s: %v", addr, err))
			} else {
				conn.Close()
				probeCheck.Status = models.StatusPass
				probeCheck.Summary = fmt.Sprintf("probe %q reachable at %s:22", p.Name, p.Host)
				probeCheck.Observed["reachable"] = true
			}
			probeCheck.Finish()
			checks = append(checks, *probeCheck)
		}
	}

	return checks
}

func doctorTag(s models.Status) string {
	switch s {
	case models.StatusPass:
		return "[ OK ]"
	case models.StatusFail:
		return "[FAIL]"
	case models.StatusWarn:
		return "[WARN]"
	default:
		return "[ERR ]"
	}
}

func nmapInstallHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Install nmap: winget install nmap"
	case "darwin":
		return "Install nmap: brew install nmap"
	default:
		return "Install nmap: sudo apt install nmap (Debian/Ubuntu) or sudo dnf install nmap (Fedora/RHEL)"
	}
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
