package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var artifactLabelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)

var classicPCAPMagic = map[[4]byte]struct{}{
	{0xd4, 0xc3, 0xb2, 0xa1}: {},
	{0xa1, 0xb2, 0xc3, 0xd4}: {},
	{0x4d, 0x3c, 0xb2, 0xa1}: {},
	{0xa1, 0xb2, 0x3c, 0x4d}: {},
}

type releaseArtifact struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type pinnedDirectory struct {
	path   string
	handle *os.File
	info   os.FileInfo
}

func pinDirectory(path string) (*pinnedDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("directory must be an absolute canonical path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("directory and its parents must not be symlinks")
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownerOK || stat.Uid != uint32(os.Geteuid()) {
		_ = handle.Close()
		return nil, errors.New("directory must be owned by the runner and must not be group-writable or world-writable")
	}
	pathInfo, err := os.Stat(path)
	if err != nil || !os.SameFile(info, pathInfo) {
		_ = handle.Close()
		return nil, errors.New("directory changed while it was pinned")
	}
	return &pinnedDirectory{path: path, handle: handle, info: info}, nil
}

func (directory *pinnedDirectory) Verify() error {
	if directory == nil || directory.handle == nil {
		return errors.New("pinned directory is required")
	}
	handleInfo, err := directory.handle.Stat()
	if err != nil || !os.SameFile(directory.info, handleInfo) {
		return errors.New("pinned directory handle changed")
	}
	pathInfo, err := os.Stat(directory.path)
	if err != nil {
		return errors.New("pinned directory path identity or permissions changed")
	}
	stat, ownerOK := pathInfo.Sys().(*syscall.Stat_t)
	if !os.SameFile(directory.info, pathInfo) || pathInfo.Mode().Perm()&0o022 != 0 || !ownerOK || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("pinned directory path identity or permissions changed")
	}
	return nil
}

func (directory *pinnedDirectory) Close() error {
	if directory == nil || directory.handle == nil {
		return nil
	}
	return directory.handle.Close()
}

type artifactDestination struct {
	root         *pinnedDirectory
	reportParent *pinnedDirectory
	reportPath   string
}

func newArtifactDestination(artifactDir, reportPath string) (_ *artifactDestination, resultErr error) {
	root, err := pinDirectory(artifactDir)
	if err != nil {
		return nil, fmt.Errorf("artifact directory: %w", err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, root.Close())
		}
	}()
	directory, err := os.Open(artifactDir)
	if err != nil {
		return nil, fmt.Errorf("open artifact directory: %w", err)
	}
	names, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("inspect artifact directory: %w", errors.Join(readErr, closeErr))
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(names) != 0 {
		return nil, errors.New("artifact directory must be initially empty")
	}
	if !filepath.IsAbs(reportPath) || filepath.Clean(reportPath) != reportPath {
		return nil, errors.New("report path must be an absolute canonical path")
	}
	reportParent, err := pinDirectory(filepath.Dir(reportPath))
	if err != nil {
		return nil, fmt.Errorf("report parent: %w", err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, reportParent.Close())
		}
	}()
	relativeReport, err := filepath.Rel(artifactDir, reportPath)
	if err != nil {
		return nil, err
	}
	if relativeReport == "." || (relativeReport != ".." && !strings.HasPrefix(relativeReport, ".."+string(filepath.Separator))) {
		return nil, errors.New("report path must be outside the artifact directory")
	}
	return &artifactDestination{root: root, reportParent: reportParent, reportPath: reportPath}, nil
}

func (destination *artifactDestination) Verify() error {
	if destination == nil {
		return errors.New("artifact destination is required")
	}
	return errors.Join(destination.root.Verify(), destination.reportParent.Verify())
}

func (destination *artifactDestination) Close() error {
	if destination == nil {
		return nil
	}
	return errors.Join(destination.root.Close(), destination.reportParent.Close())
}

type packetCapture struct {
	command *exec.Cmd
	path    string
	stderr  strings.Builder
	done    chan error
	stop    sync.Once
	err     error
}

var packetCaptureCommand = func(ctx context.Context, namespace, networkInterface, outputPath string) *exec.Cmd {
	arguments := []string{"-U", "-n", "-s", "0", "-i", networkInterface, "-w", outputPath}
	if namespace == "" {
		return exec.CommandContext(ctx, "tcpdump", arguments...)
	}
	return exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", namespace, "tcpdump"}, arguments...)...)
}

func startPacketCapture(ctx context.Context, namespace, networkInterface, outputPath string) (*packetCapture, error) {
	if networkInterface == "" || !filepath.IsAbs(outputPath) {
		return nil, errors.New("packet capture requires an interface and absolute output path")
	}
	capture := &packetCapture{path: outputPath, done: make(chan error, 1)}
	capture.command = packetCaptureCommand(ctx, namespace, networkInterface, outputPath)
	capture.command.Stderr = &capture.stderr
	if err := capture.command.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}
	go func() { capture.done <- capture.command.Wait() }()
	readyDeadline := time.NewTimer(5 * time.Second)
	defer readyDeadline.Stop()
	readyPoll := time.NewTicker(10 * time.Millisecond)
	defer readyPoll.Stop()
	for {
		select {
		case err := <-capture.done:
			return nil, fmt.Errorf("tcpdump exited before capture became ready: %w: %s", err, strings.TrimSpace(capture.stderr.String()))
		case <-readyDeadline.C:
			_ = capture.command.Process.Kill()
			<-capture.done
			return nil, errors.New("tcpdump did not initialize its pcap within 5 seconds")
		case <-readyPoll.C:
			if info, err := os.Stat(outputPath); err == nil && info.Mode().IsRegular() && info.Size() >= 24 {
				return capture, nil
			}
		}
	}
}

func (capture *packetCapture) Stop() error {
	if capture == nil {
		return errors.New("packet capture is required")
	}
	capture.stop.Do(func() {
		if err := capture.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			capture.err = err
		}
		select {
		case err := <-capture.done:
			if err != nil {
				capture.err = errors.Join(capture.err, fmt.Errorf("tcpdump: %w: %s", err, strings.TrimSpace(capture.stderr.String())))
			}
		case <-time.After(5 * time.Second):
			capture.err = errors.Join(capture.err, errors.New("tcpdump did not stop within 5 seconds"), capture.command.Process.Kill())
			<-capture.done
		}
		value, err := os.ReadFile(capture.path)
		if err != nil || !validClassicPCAP(value) {
			capture.err = errors.Join(capture.err, errors.New("tcpdump did not produce a non-empty classic pcap"), err)
		}
	})
	return capture.err
}

func validClassicPCAP(value []byte) bool {
	if len(value) <= 24 {
		return false
	}
	var magic [4]byte
	copy(magic[:], value[:4])
	_, ok := classicPCAPMagic[magic]
	return ok
}

type runEvidence struct {
	destination  *artifactDestination
	reportParent string
	directory    string
	qlogDir      string
	capture      *packetCapture
	once         sync.Once
	artifacts    []releaseArtifact
	err          error
}

func startRunEvidence(ctx context.Context, destination *artifactDestination, label, namespace, networkInterface string) (*runEvidence, error) {
	if !artifactLabelPattern.MatchString(label) {
		return nil, errors.New("invalid release artifact label")
	}
	if err := destination.Verify(); err != nil {
		return nil, err
	}
	directory := filepath.Join(destination.root.path, label)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	if err := destination.Verify(); err != nil {
		return nil, err
	}
	qlogDir := filepath.Join(directory, "qlog")
	if err := os.Mkdir(qlogDir, 0o700); err != nil {
		return nil, err
	}
	capture, err := startPacketCapture(ctx, namespace, networkInterface, filepath.Join(directory, "traffic.pcap"))
	if err != nil {
		return nil, err
	}
	return &runEvidence{
		destination: destination, reportParent: destination.reportParent.path, directory: directory,
		qlogDir: qlogDir, capture: capture,
	}, nil
}

func (evidence *runEvidence) Finish() ([]releaseArtifact, error) {
	evidence.once.Do(func() {
		evidence.err = evidence.capture.Stop()
		evidence.err = errors.Join(evidence.err, evidence.destination.Verify())
		artifacts, err := summarizeArtifacts(evidence.reportParent, evidence.directory)
		evidence.artifacts = artifacts
		evidence.err = errors.Join(evidence.err, err)
		evidence.err = errors.Join(evidence.err, evidence.destination.Verify())
	})
	return append([]releaseArtifact(nil), evidence.artifacts...), evidence.err
}

func summarizeArtifacts(reportParent, directory string) ([]releaseArtifact, error) {
	var artifacts []releaseArtifact
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release artifact %s is not a regular file", path)
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(value)
		relative, err := filepath.Rel(reportParent, path)
		if err != nil || relative == "." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("release artifact is outside the report directory")
		}
		var kind string
		switch {
		case filepath.Base(path) == "traffic.pcap" && validClassicPCAP(value):
			kind = "classic-pcap"
		case filepath.Ext(path) == ".sqlog" && len(value) != 0:
			kind = "qlog-json-seq"
		default:
			return fmt.Errorf("release artifact %s is not a recognized non-empty pcap or qlog", path)
		}
		artifacts = append(artifacts, releaseArtifact{
			Kind: kind, Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(digest[:]), SizeBytes: info.Size(),
		})
		return nil
	})
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Path < artifacts[right].Path })
	return artifacts, err
}

func commandEnvironmentWithQLOG(directory string) []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "QLOGDIR=") && !strings.HasPrefix(item, "FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE=") {
			environment = append(environment, item)
		}
	}
	return append(environment, "QLOGDIR="+directory, "FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE=1")
}
