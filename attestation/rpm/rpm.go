package rpm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "rpm"
	Type    = "https://testifysec.com/attestations/rpm/v1.0"
	RunType = attestation.ProductRunType
)

// Register the attestor
func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	// Core Package Information
	PackageName  string `json:"name"`
	Epoch        string `json:"epoch,omitempty"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
	Summary      string `json:"summary,omitempty"`
	Description  string `json:"description,omitempty"`
	
	// Build Information
	BuildHost    string    `json:"build_host,omitempty"`
	BuildTime    time.Time `json:"build_time,omitempty"`
	SourceRPM    string    `json:"source_rpm,omitempty"`
	Vendor       string    `json:"vendor,omitempty"`
	Packager     string    `json:"packager,omitempty"`
	License      string    `json:"license,omitempty"`
	URL          string    `json:"url,omitempty"`
	Distribution string    `json:"distribution,omitempty"`
	
	// Signature Information
	Signature    *RPMSignature `json:"signature,omitempty"`
	
	// Dependencies (will be subjects)
	Requires     []string `json:"requires,omitempty"`
	Provides     []string `json:"provides,omitempty"`
	Conflicts    []string `json:"conflicts,omitempty"`
	Obsoletes    []string `json:"obsoletes,omitempty"`
	
	// File Information
	Files        []RPMFile `json:"files,omitempty"`
	
	// Scriptlets
	PreInstall   string `json:"pre_install,omitempty"`
	PostInstall  string `json:"post_install,omitempty"`
	PreUninstall string `json:"pre_uninstall,omitempty"`
	PostUninstall string `json:"post_uninstall,omitempty"`
	
	// Verification Status (if installed)
	Installed    bool   `json:"installed"`
	VerifyStatus string `json:"verify_status,omitempty"`
	
	// The RPM file being analyzed
	RPMFile      string `json:"rpm_file,omitempty"`
}

type RPMSignature struct {
	KeyID       string `json:"key_id,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	Valid       bool   `json:"valid"`
	SignedBy    string `json:"signed_by,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RPMFile struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Mode        string `json:"mode"`
	User        string `json:"user"`
	Group       string `json:"group"`
	Digest      string `json:"digest,omitempty"`
	IsConfig    bool   `json:"is_config"`
	IsDoc       bool   `json:"is_doc"`
	IsGhost     bool   `json:"is_ghost"`
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Check if rpm command is available
	if !isRPMAvailable() {
		return fmt.Errorf("rpm command not found - RPM attestor requires rpm tools")
	}
	
	// Look for RPM files in the working directory
	rpmFiles, err := findRPMFiles(ctx.WorkingDir())
	if err != nil {
		return fmt.Errorf("failed to find RPM files: %w", err)
	}
	
	if len(rpmFiles) == 0 {
		// No RPM files found, check if this is an installed package query
		return fmt.Errorf("no RPM files found in working directory")
	}
	
	// For now, analyze the first RPM file found
	// TODO: Support analyzing multiple RPMs or specific RPM selection
	rpmFile := rpmFiles[0]
	a.RPMFile = rpmFile
	
	// Extract basic package information
	if err := a.extractPackageInfo(rpmFile); err != nil {
		return fmt.Errorf("failed to extract package info: %w", err)
	}
	
	// Extract dependencies
	if err := a.extractDependencies(rpmFile); err != nil {
		return fmt.Errorf("failed to extract dependencies: %w", err)
	}
	
	// Extract file list
	if err := a.extractFiles(rpmFile); err != nil {
		return fmt.Errorf("failed to extract files: %w", err)
	}
	
	// Extract scriptlets
	if err := a.extractScriptlets(rpmFile); err != nil {
		return fmt.Errorf("failed to extract scriptlets: %w", err)
	}
	
	// Verify signature
	if err := a.verifySignature(rpmFile); err != nil {
		// Don't fail on signature verification errors, just log
		// Some RPMs might not be signed
		fmt.Fprintf(os.Stderr, "Warning: signature verification failed: %v\n", err)
	}
	
	return nil
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestor{})
}

// Helper functions

func isRPMAvailable() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

func findRPMFiles(dir string) ([]string, error) {
	var rpmFiles []string
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".rpm") {
			rpmFiles = append(rpmFiles, path)
		}
		
		return nil
	})
	
	return rpmFiles, err
}

func (a *Attestor) extractPackageInfo(rpmFile string) error {
	// Extract basic package information using rpm -qp
	cmd := exec.Command("rpm", "-qp", rpmFile, "--queryformat",
		"%{NAME}\\n%{EPOCH}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n%{SUMMARY}\\n%{DESCRIPTION}\\n%{BUILDHOST}\\n%{BUILDTIME}\\n%{SOURCERPM}\\n%{VENDOR}\\n%{PACKAGER}\\n%{LICENSE}\\n%{URL}\\n%{DISTRIBUTION}")
	
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query RPM: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	if len(lines) < 15 {
		return fmt.Errorf("unexpected rpm query output format")
	}
	
	a.PackageName = strings.TrimSpace(lines[0])
	a.Epoch = strings.TrimSpace(lines[1])
	a.Version = strings.TrimSpace(lines[2])
	a.Release = strings.TrimSpace(lines[3])
	a.Architecture = strings.TrimSpace(lines[4])
	a.Summary = strings.TrimSpace(lines[5])
	a.Description = strings.TrimSpace(lines[6])
	a.BuildHost = strings.TrimSpace(lines[7])
	
	// Parse build time
	if buildTimeStr := strings.TrimSpace(lines[8]); buildTimeStr != "" && buildTimeStr != "(none)" {
		if buildTime, err := strconv.ParseInt(buildTimeStr, 10, 64); err == nil {
			a.BuildTime = time.Unix(buildTime, 0)
		}
	}
	
	a.SourceRPM = strings.TrimSpace(lines[9])
	a.Vendor = strings.TrimSpace(lines[10])
	a.Packager = strings.TrimSpace(lines[11])
	a.License = strings.TrimSpace(lines[12])
	a.URL = strings.TrimSpace(lines[13])
	a.Distribution = strings.TrimSpace(lines[14])
	
	// Clean up empty fields
	if a.Epoch == "(none)" {
		a.Epoch = ""
	}
	
	return nil
}

func (a *Attestor) extractDependencies(rpmFile string) error {
	// Extract requires
	cmd := exec.Command("rpm", "-qp", rpmFile, "--requires")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query requires: %w", err)
	}
	a.Requires = parseDepList(string(output))
	
	// Extract provides
	cmd = exec.Command("rpm", "-qp", rpmFile, "--provides")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query provides: %w", err)
	}
	a.Provides = parseDepList(string(output))
	
	// Extract conflicts
	cmd = exec.Command("rpm", "-qp", rpmFile, "--conflicts")
	output, err = cmd.Output()
	if err == nil { // conflicts might not exist
		a.Conflicts = parseDepList(string(output))
	}
	
	// Extract obsoletes
	cmd = exec.Command("rpm", "-qp", rpmFile, "--obsoletes")
	output, err = cmd.Output()
	if err == nil { // obsoletes might not exist
		a.Obsoletes = parseDepList(string(output))
	}
	
	return nil
}

func parseDepList(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var deps []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "(none)" {
			deps = append(deps, line)
		}
	}
	
	return deps
}

func (a *Attestor) extractFiles(rpmFile string) error {
	// Get file list with detailed information
	cmd := exec.Command("rpm", "-qpl", rpmFile)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query files: %w", err)
	}
	
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	a.Files = make([]RPMFile, 0, len(files))
	
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file != "" {
			// TODO: Extract detailed file information (size, permissions, etc.)
			// This would require additional rpm queries or parsing
			a.Files = append(a.Files, RPMFile{
				Path: file,
			})
		}
	}
	
	return nil
}

func (a *Attestor) extractScriptlets(rpmFile string) error {
	// Extract pre-install script
	cmd := exec.Command("rpm", "-qp", rpmFile, "--queryformat", "%{PREIN}")
	if output, err := cmd.Output(); err == nil {
		script := strings.TrimSpace(string(output))
		if script != "" && script != "(none)" {
			a.PreInstall = script
		}
	}
	
	// Extract post-install script
	cmd = exec.Command("rpm", "-qp", rpmFile, "--queryformat", "%{POSTIN}")
	if output, err := cmd.Output(); err == nil {
		script := strings.TrimSpace(string(output))
		if script != "" && script != "(none)" {
			a.PostInstall = script
		}
	}
	
	// Extract pre-uninstall script
	cmd = exec.Command("rpm", "-qp", rpmFile, "--queryformat", "%{PREUN}")
	if output, err := cmd.Output(); err == nil {
		script := strings.TrimSpace(string(output))
		if script != "" && script != "(none)" {
			a.PreUninstall = script
		}
	}
	
	// Extract post-uninstall script
	cmd = exec.Command("rpm", "-qp", rpmFile, "--queryformat", "%{POSTUN}")
	if output, err := cmd.Output(); err == nil {
		script := strings.TrimSpace(string(output))
		if script != "" && script != "(none)" {
			a.PostUninstall = script
		}
	}
	
	return nil
}

func (a *Attestor) verifySignature(rpmFile string) error {
	// Check if the RPM is signed
	cmd := exec.Command("rpm", "-K", rpmFile)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check signature: %w", err)
	}
	
	sigInfo := strings.TrimSpace(string(output))
	a.Signature = &RPMSignature{}
	
	// Parse signature information
	if strings.Contains(sigInfo, "OK") {
		a.Signature.Valid = true
	}
	
	if strings.Contains(sigInfo, "NOT OK") || strings.Contains(sigInfo, "MISSING KEYS") {
		a.Signature.Valid = false
	}
	
	// Extract key ID if available
	// This is a simplified parser - real implementation would need more robust parsing
	if strings.Contains(sigInfo, "Key ID") {
		parts := strings.Split(sigInfo, "Key ID")
		if len(parts) > 1 {
			keyPart := strings.TrimSpace(parts[1])
			if keyFields := strings.Fields(keyPart); len(keyFields) > 0 {
				a.Signature.KeyID = keyFields[0]
			}
		}
	}
	
	return nil
}