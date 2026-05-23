package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/logger"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/report"
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

		// 1. nmap installed
		nmapCheck := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
		if nmap.Available() {
			path, _ := exec.LookPath("nmap")
			out, err := exec.Command(path, "--version").Output()
			ver := "unknown version"
			if err == nil && len(out) > 0 {
				line := string(out)
				if nl := len(line); nl > 60 {
					line = line[:60]
				}
				ver = line
			}
			nmapCheck.Status = models.StatusPass
			nmapCheck.Summary = fmt.Sprintf("nmap found: %s", ver)
		} else {
			nmapCheck.Status = models.StatusFail
			nmapCheck.Summary = "nmap is not installed or not in PATH"
			nmapCheck.Violations = append(nmapCheck.Violations, nmapInstallHint())
			allPass = false
		}
		nmapCheck.Finish()
		checks = append(checks, *nmapCheck)

		// 2. Platform detection
		platCheck := models.NewCheckResult("doctor", "platform", "local", runtime.GOOS)
		platCheck.Status = models.StatusPass
		platCheck.Summary = fmt.Sprintf("platform: %s/%s", runtime.GOOS, runtime.GOARCH)
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
			logDirCheck.Summary = fmt.Sprintf("cannot create log directory %s: %v", logDir, err)
			allPass = false
		} else {
			testFile := logDir + "/.nyx_write_test"
			if f, err := os.Create(testFile); err != nil {
				logDirCheck.Status = models.StatusFail
				logDirCheck.Summary = fmt.Sprintf("log directory %s is not writable: %v", logDir, err)
				allPass = false
			} else {
				f.Close()
				os.Remove(testFile)
				logDirCheck.Status = models.StatusPass
				logDirCheck.Summary = fmt.Sprintf("log directory %s is writable", logDir)
			}
		}
		logDirCheck.Finish()
		checks = append(checks, *logDirCheck)

		// 4. Internet route (informational)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		routeCheck := models.NewCheckResult("doctor", "internet_route", "local", "8.8.8.8")
		if route, err := system.GetRouteToTarget(ctx, "8.8.8.8"); err != nil {
			routeCheck.Status = models.StatusWarn
			routeCheck.Summary = "no route to 8.8.8.8 — internet connectivity may be unavailable"
		} else {
			routeCheck.Status = models.StatusPass
			routeCheck.Summary = fmt.Sprintf("internet route: via %s dev %s", route.Gateway, route.Device)
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

		if allPass {
			fmt.Fprintln(w, "\nnyx environment looks healthy.")
		} else {
			fmt.Fprintln(w, "\nnyx environment has issues. See above for details.")
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
