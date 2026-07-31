package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

type mergeCapacityRequest struct {
	ManifestPath      string
	RegistryPath      string
	ReportPath        string
	ArtifactDirectory string
	PartReports       []string
}

type stringListFlag []string

func (values *stringListFlag) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("list value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type rawCapacityPart struct {
	root  string
	index rawCollectionIndex
}

func mergeCapacityCollections(request mergeCapacityRequest) error {
	root, err := canonicalDirectory(request.ArtifactDirectory, true)
	if err != nil {
		return fmt.Errorf("capacity merge artifact directory: %w", err)
	}
	report := filepath.Clean(request.ReportPath)
	if !filepath.IsAbs(request.ReportPath) || report != request.ReportPath || filepath.Dir(report) != root {
		return errors.New("capacity merge report must be a fresh direct child of the artifact directory")
	}
	if _, err := os.Lstat(report); !os.IsNotExist(err) {
		return errors.New("capacity merge report path must be fresh")
	}
	identity, err := pinCollectionDirectory(root)
	if err != nil {
		return err
	}
	defer identity.Close()

	manifestPath, manifestSHA, err := snapshotRegularFile(request.ManifestPath, false)
	if err != nil {
		return fmt.Errorf("capacity merge manifest: %w", err)
	}
	registryPath, registrySHA, err := snapshotRegularFile(request.RegistryPath, false)
	if err != nil {
		return fmt.Errorf("capacity merge registry: %w", err)
	}
	manifest, err := loadPerformanceManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	registry, err := loadCaseRegistry(registryPath)
	if err != nil {
		return err
	}
	if err := validateCaseRegistry(registry); err != nil {
		return err
	}
	plan, err := buildCollectionPlan("bench-transport-capacity", manifest, registry)
	if err != nil {
		return err
	}
	if len(plan.Missing) != 0 {
		return errors.New("capacity merge requires the complete frozen producer plan")
	}

	parts := make([]rawCapacityPart, 0, len(request.PartReports))
	for _, partReport := range request.PartReports {
		part, err := loadRawCapacityPart(root, partReport)
		if err != nil {
			return err
		}
		parts = append(parts, part)
	}
	index, locations, err := mergeRawCapacityIndexes(parts, plan)
	if err != nil {
		return err
	}
	if index.InputSHA256["manifest"] != manifestSHA || index.InputSHA256["registry"] != registrySHA {
		return errors.New("capacity parts do not match the supplied frozen manifest and registry")
	}
	for jobIndex := range index.Jobs {
		record := &index.Jobs[jobIndex]
		location := locations[record.ID]
		expected := plan.Jobs[jobIndex]
		jobDirectory := filepath.Join(location.root, filepath.FromSlash(location.record.Directory))
		commandPath := filepath.Join(jobDirectory, "command.json")
		_, commandSHA, err := snapshotRegularFile(commandPath, false)
		if err != nil || commandSHA != record.CommandSHA256 {
			return fmt.Errorf("capacity job %s command digest changed", record.ID)
		}
		reportPath := filepath.Join(jobDirectory, "cell.json")
		_, reportSHA, err := snapshotRegularFile(reportPath, false)
		if err != nil || reportSHA != record.ReportSHA {
			return fmt.Errorf("capacity job %s report digest changed", record.ID)
		}
		artifactDirectory := filepath.Join(jobDirectory, "artifacts")
		actualCaseIDs, err := validateRawCaseSuiteReport(
			reportPath, artifactDirectory, index.FinalSHA, manifest.Digest, manifestSHA, expected, registry,
		)
		if err != nil {
			return fmt.Errorf("capacity job %s raw report: %w", record.ID, err)
		}
		if !slices.Equal(actualCaseIDs, record.CaseIDs) {
			return fmt.Errorf("capacity job %s case IDs changed", record.ID)
		}
		if err := validateProducedArtifacts(artifactDirectory); err != nil {
			return fmt.Errorf("capacity job %s produced artifacts: %w", record.ID, err)
		}
		record.Directory = filepath.ToSlash(filepath.Join("parts", location.index.Batch, location.record.Directory))
	}
	if err := identity.Verify(); err != nil {
		return err
	}
	return publishRawCollection(identity, report, index)
}

func loadRawCapacityPart(root, reportPath string) (rawCapacityPart, error) {
	canonical, _, err := snapshotRegularFile(reportPath, false)
	if err != nil {
		return rawCapacityPart{}, fmt.Errorf("capacity part report: %w", err)
	}
	partRoot := filepath.Dir(canonical)
	relative, err := filepath.Rel(root, partRoot)
	if err != nil || filepath.IsAbs(relative) {
		return rawCapacityPart{}, errors.New("capacity part is outside the merge artifact directory")
	}
	components := splitCleanRelativePath(relative)
	if len(components) != 2 || components[0] != "parts" {
		return rawCapacityPart{}, errors.New("capacity part must be a direct batch directory under parts")
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		return rawCapacityPart{}, err
	}
	var index rawCollectionIndex
	if err := decodeStrictJSON(data, &index); err != nil {
		return rawCapacityPart{}, fmt.Errorf("capacity part report is not strict JSON: %w", err)
	}
	if index.Batch != components[1] {
		return rawCapacityPart{}, errors.New("capacity part batch does not match its directory")
	}
	return rawCapacityPart{root: partRoot, index: index}, nil
}

type rawCapacityJobLocation struct {
	root   string
	index  rawCollectionIndex
	record rawJobRecord
}

func mergeRawCapacityIndexes(parts []rawCapacityPart, plan collectionPlan) (rawCollectionIndex, map[string]rawCapacityJobLocation, error) {
	if len(parts) != len(capacityCollectionBatchOrder) {
		return rawCollectionIndex{}, nil, fmt.Errorf("capacity merge requires %d parts", len(capacityCollectionBatchOrder))
	}
	expectedByCase := make(map[string]collectionJob, len(plan.Jobs))
	orderByID := make(map[string]int, len(plan.Jobs))
	for index, job := range plan.Jobs {
		expectedByCase[job.CaseID] = job
		orderByID[job.ID] = index
	}
	seenBatches := make(map[string]struct{}, len(parts))
	locations := make(map[string]rawCapacityJobLocation, len(plan.Jobs))
	var merged rawCollectionIndex
	for partIndex, part := range parts {
		index := part.index
		if index.SchemaVersion != 1 || index.Classification != "raw_transport_collection_part" ||
			index.Target != "bench-transport-capacity" || !gitSHAPattern.MatchString(index.BaseSHA) ||
			!gitSHAPattern.MatchString(index.FinalSHA) || index.BaseSHA == index.FinalSHA ||
			!validRunnerLocalConfigShape(index.Runner) || !validCapacityPartInputDigests(index.InputSHA256) ||
			index.Runner.ExecutableSHA256 != index.InputSHA256["runner_executable"] ||
			index.Runner.SourceSHA256 != index.InputSHA256["runner_source"] ||
			index.Runner.ArgvSHA256 != index.InputSHA256["runner_argv"] {
			return rawCollectionIndex{}, nil, errors.New("capacity merge received an invalid partial collection")
		}
		if _, ok := capacityCollectionBatches[index.Batch]; !ok {
			return rawCollectionIndex{}, nil, fmt.Errorf("capacity merge received unknown batch %q", index.Batch)
		}
		if _, duplicate := seenBatches[index.Batch]; duplicate {
			return rawCollectionIndex{}, nil, fmt.Errorf("capacity merge received duplicate batch %s", index.Batch)
		}
		seenBatches[index.Batch] = struct{}{}
		if partIndex == 0 {
			merged = rawCollectionIndex{
				SchemaVersion: 1, Classification: "raw_transport_collection", Target: index.Target,
				BaseSHA: index.BaseSHA, FinalSHA: index.FinalSHA, Runner: index.Runner, InputSHA256: cloneStringMap(index.InputSHA256),
			}
		} else if index.BaseSHA != merged.BaseSHA || index.FinalSHA != merged.FinalSHA ||
			index.Runner != merged.Runner || !equalStringMap(index.InputSHA256, merged.InputSHA256) {
			return rawCollectionIndex{}, nil, errors.New("capacity parts do not share one source and input identity")
		}
		selected, err := selectCapacityCollectionBatch(plan, index.Batch)
		if err != nil {
			return rawCollectionIndex{}, nil, err
		}
		expectedInBatch := make(map[string]collectionJob, len(selected.Jobs))
		for _, job := range selected.Jobs {
			expectedInBatch[job.CaseID] = job
		}
		if len(index.Jobs) != len(expectedInBatch) {
			return rawCollectionIndex{}, nil, fmt.Errorf("capacity batch %s job count drifted", index.Batch)
		}
		for _, record := range index.Jobs {
			if len(record.CaseIDs) != 1 {
				return rawCollectionIndex{}, nil, fmt.Errorf("capacity job %s does not bind exactly one case", record.ID)
			}
			expected, ok := expectedInBatch[record.CaseIDs[0]]
			if !ok || expected.ID != record.ID || record.SourceSHA != index.FinalSHA {
				return rawCollectionIndex{}, nil, fmt.Errorf("capacity batch %s contains unexpected job %s", index.Batch, record.ID)
			}
			if !slices.Equal(record.CellIDs, expected.CellIDs) || record.VariantID != expected.VariantID {
				return rawCollectionIndex{}, nil, fmt.Errorf("capacity job %s producer binding drifted", record.ID)
			}
			if _, duplicate := locations[record.ID]; duplicate {
				return rawCollectionIndex{}, nil, fmt.Errorf("capacity merge received duplicate job %s", record.ID)
			}
			if record.Directory != filepath.ToSlash(filepath.Join("jobs", record.ID)) ||
				!validSHA256(record.CommandSHA256) || !validSHA256(record.ReportSHA) ||
				record.RunnerExecutableSHA256 != index.InputSHA256["runner_executable"] {
				return rawCollectionIndex{}, nil, fmt.Errorf("capacity job %s identity drifted", record.ID)
			}
			locations[record.ID] = rawCapacityJobLocation{root: part.root, index: index, record: record}
			merged.Jobs = append(merged.Jobs, record)
			delete(expectedInBatch, record.CaseIDs[0])
			delete(expectedByCase, record.CaseIDs[0])
		}
		if len(expectedInBatch) != 0 {
			return rawCollectionIndex{}, nil, fmt.Errorf("capacity batch %s is incomplete", index.Batch)
		}
	}
	if len(seenBatches) != len(capacityCollectionBatchOrder) || len(expectedByCase) != 0 || len(merged.Jobs) != len(plan.Jobs) {
		return rawCollectionIndex{}, nil, errors.New("capacity merge does not completely cover the frozen cases")
	}
	sort.Slice(merged.Jobs, func(i, j int) bool { return orderByID[merged.Jobs[i].ID] < orderByID[merged.Jobs[j].ID] })
	return merged, locations, nil
}

func validCapacityPartInputDigests(digests map[string]string) bool {
	for _, required := range []string{"manifest", "registry", "runner_executable", "runner_config", "runner_source", "runner_argv"} {
		if !validSHA256(digests[required]) {
			return false
		}
	}
	for _, digest := range digests {
		if !validSHA256(digest) {
			return false
		}
	}
	return true
}

func splitCleanRelativePath(path string) []string {
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." {
		return nil
	}
	var result []string
	for clean != "." {
		directory, base := filepath.Split(clean)
		if base == "" || base == "." || base == ".." {
			return nil
		}
		result = append([]string{base}, result...)
		clean = filepath.Clean(directory)
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
