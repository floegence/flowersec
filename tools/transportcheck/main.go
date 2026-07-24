package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: transportcheck <manifest|evidence|sign> [flags]")
	}
	switch args[0] {
	case "manifest":
		flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		manifestPath := flags.String("manifest", "", "performance manifest path")
		registryPath := flags.String("registry", "", "case registry path")
		makefilePath := flags.String("makefile", "", "optional Makefile used to verify case owner recipes")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *manifestPath == "" || *registryPath == "" || flags.NArg() != 0 {
			return errors.New("manifest requires -manifest and -registry")
		}
		manifest, err := loadPerformanceManifest(*manifestPath)
		if err != nil {
			return err
		}
		if err := validateManifest(manifest); err != nil {
			return err
		}
		registry, err := loadCaseRegistry(*registryPath)
		if err != nil {
			return err
		}
		if err := validateCaseRegistry(registry); err != nil {
			return err
		}
		if *makefilePath != "" {
			if err := validateCaseOwnerRecipes(registry, *makefilePath); err != nil {
				return err
			}
		}
		loads, err := allocateLPT(manifest.Cells, manifest.EligibleLaneCount)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(output, "manifest pass: digest=%s runs=%d cells=%d lane_loads_minutes=%v cases=%d\n", manifest.Digest, manifest.RunCount, len(manifest.Cells), loads, len(registry.Cases))
		return nil
	case "evidence":
		flags := flag.NewFlagSet("evidence", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		manifestPath := flags.String("manifest", "", "performance manifest path")
		registryPath := flags.String("registry", "", "case registry path")
		reportPath := flags.String("report", "", "evidence report path")
		repositoryPath := flags.String("repo", "", "audited Git repository path")
		baseSHA := flags.String("base-sha", "", "audited base Git SHA")
		trustStorePath := flags.String("trust-store", "", "independent evidence signer trust store path")
		trustPolicyPath := flags.String("trust-policy", "", "repository-audited evidence trust policy path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *manifestPath == "" || *registryPath == "" || *reportPath == "" || *repositoryPath == "" || *baseSHA == "" || *trustStorePath == "" || *trustPolicyPath == "" || flags.NArg() != 0 {
			return errors.New("evidence requires -manifest, -registry, -report, -repo, -base-sha, -trust-store, and -trust-policy")
		}
		_, _, _, result, err := validateEvidenceBundle(*manifestPath, *registryPath, *reportPath, *repositoryPath, *baseSHA, *trustStorePath, *trustPolicyPath, true)
		if err != nil {
			return err
		}
		for _, issue := range result.Issues {
			_, _ = fmt.Fprintln(output, issue)
		}
		if result.Status != statusPass {
			return fmt.Errorf("evidence %s: %d issue(s)", result.Status, len(result.Issues))
		}
		_, _ = fmt.Fprintln(output, "evidence pass")
		return nil
	case "sign":
		flags := flag.NewFlagSet("sign", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		manifestPath := flags.String("manifest", "", "performance manifest path")
		registryPath := flags.String("registry", "", "case registry path")
		reportPath := flags.String("report", "", "unsigned evidence report path")
		outputPath := flags.String("output", "", "new signed evidence report path")
		repositoryPath := flags.String("repo", "", "audited Git repository path")
		baseSHA := flags.String("base-sha", "", "audited base Git SHA")
		trustStorePath := flags.String("trust-store", "", "independent evidence signer trust store path")
		trustPolicyPath := flags.String("trust-policy", "", "repository-audited evidence trust policy path")
		keyPath := flags.String("key-file", "", "offline Ed25519 PKCS#8 private key path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *manifestPath == "" || *registryPath == "" || *reportPath == "" || *outputPath == "" || *repositoryPath == "" || *baseSHA == "" || *trustStorePath == "" || *trustPolicyPath == "" || *keyPath == "" || flags.NArg() != 0 {
			return errors.New("sign requires -manifest, -registry, -report, -output, -repo, -base-sha, -trust-store, -trust-policy, and -key-file")
		}
		if err := validateSigningPaths(*reportPath, *outputPath); err != nil {
			return err
		}
		report, trustStore, trustPolicy, result, err := validateEvidenceBundle(*manifestPath, *registryPath, *reportPath, *repositoryPath, *baseSHA, *trustStorePath, *trustPolicyPath, false)
		if err != nil {
			return err
		}
		for _, issue := range result.Issues {
			_, _ = fmt.Fprintln(output, issue)
		}
		if result.Status != statusPass {
			return fmt.Errorf("unsigned evidence %s: %d issue(s)", result.Status, len(result.Issues))
		}
		if report.Attestation != (EvidenceAttestation{}) {
			return errors.New("unsigned evidence report already contains attestation data")
		}
		privateKey, err := loadEd25519PKCS8PrivateKey(*keyPath)
		if err != nil {
			return err
		}
		defer clear(privateKey)
		if err := requirePrivateKeyMatchesTrustStore(privateKey, trustStore, trustPolicy.KeyID); err != nil {
			return err
		}
		if err := signEvidenceAttestation(report, trustPolicy.KeyID, privateKey); err != nil {
			return err
		}
		if err := writeNewEvidenceReport(*outputPath, report); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(output, "evidence signed")
		return nil
	case "gate":
		flags := flag.NewFlagSet("gate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		metaPath := flags.String("meta", "", "evidence meta-schema path")
		target := flags.String("target", "", "Make target name")
		classification := flags.String("classification", "", "declared evidence classification")
		reportPath := flags.String("report", "", "optional emitted report path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *metaPath == "" || *target == "" || *classification == "" || flags.NArg() != 0 {
			return errors.New("gate requires -meta, -target, and -classification")
		}
		meta, err := loadEvidenceMetaSchema(*metaPath)
		if err != nil {
			return err
		}
		if err := validateGateReport(meta, *target, *classification, *reportPath); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(output, "gate pass: target=%s classification=%s\n", *target, *classification)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func validateEvidenceBundle(manifestPath, registryPath, reportPath, repositoryPath, baseSHA, trustStorePath, trustPolicyPath string, requireAttestation bool) (*EvidenceReport, *EvidenceTrustStore, *EvidenceTrustPolicy, CheckResult, error) {
	manifest, err := loadPerformanceManifest(manifestPath)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	registry, err := loadCaseRegistry(registryPath)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	report, err := loadEvidenceReport(reportPath)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	trustStore, err := loadEvidenceTrustStore(trustStorePath)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	trustPolicy, err := loadEvidenceTrustPolicy(trustPolicyPath)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	if err := validateTrustStoreAgainstPolicy(trustStorePath, trustStore, trustPolicy); err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	if requireAttestation {
		if err := verifyEvidenceAttestation(report, trustStore); err != nil {
			return nil, nil, nil, CheckResult{}, err
		}
	}
	if err := validateRunnerAgainstPolicy(report.Runner, trustPolicy); err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	repository, err := inspectRepository(repositoryPath, baseSHA)
	if err != nil {
		return nil, nil, nil, CheckResult{}, err
	}
	result := checkEvidenceAgainstRepository(manifest, registry, report, report.baseDir, repository)
	return report, trustStore, trustPolicy, result, nil
}
