package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var typedArtifactStemPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)

// typedArtifactWriter creates immutable evidence artifacts and their signed
// metadata inputs. It rejects content reuse because the evidence checker binds
// one artifact digest to exactly one claim.
type typedArtifactWriter struct {
	directory *collectionDirectoryIdentity
	digests   map[string]string
	created   []string
}

func newTypedArtifactWriter(directory string) (*typedArtifactWriter, error) {
	canonical, err := canonicalDirectory(directory, true)
	if err != nil {
		return nil, err
	}
	identity, err := pinCollectionDirectory(canonical)
	if err != nil {
		return nil, err
	}
	return &typedArtifactWriter{directory: identity, digests: make(map[string]string)}, nil
}

func (writer *typedArtifactWriter) Close() error {
	if writer == nil || writer.directory == nil {
		return nil
	}
	return writer.directory.Close()
}

func (writer *typedArtifactWriter) WriteJSON(context, kind, stem string, value any) (EvidenceArtifact, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	data = append(data, '\n')
	return writer.Write(context, kind, stem, ".json", data)
}

func (writer *typedArtifactWriter) Write(context, kind, stem, extension string, data []byte) (_ EvidenceArtifact, resultErr error) {
	if writer == nil || writer.directory == nil || writer.directory.handle == nil {
		return EvidenceArtifact{}, errors.New("typed artifact writer is closed")
	}
	if context == "" || kind == "" || !typedArtifactStemPattern.MatchString(stem) ||
		(extension != ".json" && extension != ".pcap" && extension != ".qlog") || len(data) == 0 {
		return EvidenceArtifact{}, errors.New("typed artifact claim is invalid")
	}
	if err := writer.directory.Verify(); err != nil {
		return EvidenceArtifact{}, err
	}
	digest := sha256.Sum256(data)
	digestText := hex.EncodeToString(digest[:])
	claim := context + " " + kind
	if previous, exists := writer.digests[digestText]; exists {
		return EvidenceArtifact{}, fmt.Errorf("typed artifact digest is already claimed by %s", previous)
	}
	nameDigest := sha256.Sum256(append([]byte(context+"\x00"+kind+"\x00"), digest[:]...))
	name := fmt.Sprintf("%s-%s%s", stem, hex.EncodeToString(nameDigest[:8]), extension)
	metadataName := name + ".meta.json"
	artifact := EvidenceArtifact{Path: name, SHA256: digestText, MetaPath: metadataName}
	metadata := ArtifactMetadata{
		SchemaVersion: 1, Context: context, Kind: kind,
		ArtifactPath: name, ArtifactSHA256: digestText,
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return EvidenceArtifact{}, err
	}
	metadataData = append(metadataData, '\n')
	metadataDigest := sha256.Sum256(metadataData)
	artifact.MetaSHA256 = hex.EncodeToString(metadataDigest[:])

	artifactPath := filepath.Join(writer.directory.path, name)
	metadataPath := filepath.Join(writer.directory.path, metadataName)
	if err := writeExclusiveSyncedFile(artifactPath, data); err != nil {
		return EvidenceArtifact{}, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, removeIfPresent(artifactPath), removeIfPresent(metadataPath))
		}
	}()
	if err := writeExclusiveSyncedFile(metadataPath, metadataData); err != nil {
		return EvidenceArtifact{}, err
	}
	if err := writer.directory.Verify(); err != nil {
		return EvidenceArtifact{}, err
	}
	writer.digests[digestText] = claim
	writer.created = append(writer.created, artifactPath, metadataPath)
	return artifact, nil
}

func (writer *typedArtifactWriter) checkpoint() int {
	if writer == nil {
		return 0
	}
	return len(writer.created)
}

func (writer *typedArtifactWriter) rollback(checkpoint int) error {
	if writer == nil || checkpoint < 0 || checkpoint > len(writer.created) {
		return errors.New("typed artifact rollback checkpoint is invalid")
	}
	var result error
	for index := len(writer.created) - 1; index >= checkpoint; index-- {
		result = errors.Join(result, removeIfPresent(writer.created[index]))
	}
	writer.created = writer.created[:checkpoint]
	writer.digests = make(map[string]string)
	for index := 0; index+1 < len(writer.created); index += 2 {
		data, err := os.ReadFile(writer.created[index])
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		digest := sha256.Sum256(data)
		writer.digests[hex.EncodeToString(digest[:])] = "prior typed artifact claim"
	}
	return result
}

func removeIfPresent(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writeExclusiveSyncedFile(path string, data []byte) (resultErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}
