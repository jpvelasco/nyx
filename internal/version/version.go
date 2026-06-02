package version

// Version is the single source of truth for the nyx release version.
// It is set at build time via -ldflags for releases (see Makefile release target).
var Version = "0.1.0"
