package linuxnetlab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	LossNone     = "none"
	LossPeriodic = "periodic"
	LossBurst    = "burst"

	bpfPinRoot              = "/sys/fs/bpf"
	faultStatsMapValueBytes = 200
)

var bpfTool = configuredBPFTool()

func configuredBPFTool() string {
	if value := os.Getenv("FLOWERSEC_HOST_BPFTOOL"); value != "" {
		return value
	}
	return "bpftool"
}

type FaultProfile struct {
	BPFObject         string
	BaseDelay         time.Duration
	Jitter            []time.Duration
	LossMode          string
	EveryNth          int
	BlockSize         int
	BurstFirst        int
	BurstLast         int
	RateBitsPerSecond int
	TokenBurstBytes   int
	QueueBytes        int
	LinkMTU           int
	ReorderPercent    int
	DuplicatePercent  int
	OutageStart       time.Duration
	OutageDuration    time.Duration
	ReorderDelay      time.Duration
}

// ResetFaultObservation starts packet timing and counters at the workload
// boundary instead of including endpoint setup traffic.
func ResetFaultObservation(ctx context.Context, clientNamespace, serverNamespace string) error {
	return resetFaultObservation(ctx, ExecRunner{}, clientNamespace, serverNamespace)
}

func resetFaultObservation(ctx context.Context, runner CommandRunner, clientNamespace, serverNamespace string) error {
	if runner == nil || !identifierPattern.MatchString(clientNamespace) || !identifierPattern.MatchString(serverNamespace) {
		return errors.New("valid runner and network namespaces are required to reset fault observation")
	}
	zeroValue := make([]byte, faultStatsMapValueBytes)
	for _, direction := range []string{"client", "server"} {
		path := filepath.Join(bpfPinRoot, "flowersec-"+clientNamespace+"-"+serverNamespace, direction, "maps", "flowersec_fault_stats")
		arguments := []string{"map", "update", "pinned", path, "key", "hex", "00", "00", "00", "00", "value", "hex"}
		arguments = append(arguments, byteArguments(zeroValue)...)
		if err := runner.Run(ctx, bpfTool, arguments...); err != nil {
			return fmt.Errorf("reset %s fault observation: %w", direction, err)
		}
	}
	return nil
}

func (lab *Lab) ApplyFaultProfile(ctx context.Context, profile FaultProfile) (resultErr error) {
	if err := validateFaultProfile(profile); err != nil {
		return err
	}
	object, err := verifiedBPFObject(profile.BPFObject)
	if err != nil {
		return err
	}
	if profile.LinkMTU != lab.config.LinkMTU {
		return errors.New("fault profile MTU differs from the network lab")
	}
	defer func() {
		if resultErr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultErr = errors.Join(resultErr, lab.rollback(cleanupCtx))
		cancel()
	}()
	labDirectory := filepath.Join(bpfPinRoot, "flowersec-"+lab.config.ClientNamespace+"-"+lab.config.ServerNamespace)
	if err := lab.managed(ctx, command{"mkdir", []string{labDirectory}}, command{"rmdir", []string{labDirectory}}); err != nil {
		return err
	}
	directions := []struct {
		name      string
		namespace string
		device    string
	}{
		{"client", lab.config.ClientNamespace, lab.config.ClientInterface},
		{"server", lab.config.ServerNamespace, lab.config.ServerInterface},
	}
	for _, direction := range directions {
		if err := lab.applyDirection(ctx, labDirectory, object, profile, direction.name, direction.namespace, direction.device); err != nil {
			return err
		}
	}
	return nil
}

func (lab *Lab) applyDirection(ctx context.Context, labDirectory, object string, profile FaultProfile, name, namespace, device string) error {
	directory := filepath.Join(labDirectory, name)
	maps := filepath.Join(directory, "maps")
	program := filepath.Join(directory, "program")
	configMap := filepath.Join(maps, "flowersec_fault_config")
	statsMap := filepath.Join(maps, "flowersec_fault_stats")
	if err := lab.managed(ctx, command{"mkdir", []string{directory}}, command{"rmdir", []string{directory}}); err != nil {
		return err
	}
	if err := lab.managed(ctx, command{"mkdir", []string{maps}}, command{"rmdir", []string{maps}}); err != nil {
		return err
	}
	lab.addCleanup(command{"rm", []string{"-f", configMap}})
	lab.addCleanup(command{"rm", []string{"-f", statsMap}})
	lab.addCleanup(command{"rm", []string{"-f", program}})
	if err := lab.run(ctx, command{bpfTool, []string{"prog", "load", object, program, "type", "classifier", "pinmaps", maps}}); err != nil {
		return err
	}
	networkCommand := func(args ...string) command {
		return command{"nsenter", append([]string{"--net=/var/run/netns/" + namespace, "--"}, args...)}
	}
	ifb := device + "i"
	mtu := strconv.Itoa(profile.LinkMTU)
	if err := lab.run(ctx, networkCommand(
		"ip", "link", "set", "dev", device,
		"gso_max_segs", "1", "gso_max_size", mtu,
	)); err != nil {
		return err
	}
	if err := lab.run(ctx, networkCommand(
		"ethtool", "-K", device,
		"tx", "off", "sg", "off", "tso", "off", "gso", "off", "gro", "off",
		"tx-udp-segmentation", "off", "tx-gso-list", "off",
	)); err != nil {
		return err
	}
	if profile.LossMode == LossNone {
		encoded, err := encodeFaultConfig(profile, 0)
		if err != nil {
			return err
		}
		updateArgs := []string{"map", "update", "pinned", configMap, "key", "hex", "00", "00", "00", "00", "value", "hex"}
		if err := lab.run(ctx, command{bpfTool, append(updateArgs, byteArguments(encoded)...)}); err != nil {
			return err
		}
		clsactDelete := networkCommand("tc", "qdisc", "del", "dev", device, "clsact")
		if err := lab.managed(ctx, networkCommand("tc", "qdisc", "add", "dev", device, "clsact"), clsactDelete); err != nil {
			return err
		}
		return lab.run(ctx, networkCommand("tc", "filter", "add", "dev", device, "ingress", "pref", "10", "protocol", "all", "bpf", "direct-action", "object-pinned", program))
	}
	rate := strconv.Itoa(profile.RateBitsPerSecond) + "bit"
	burst := strconv.Itoa(profile.TokenBurstBytes) + "b"
	limit := strconv.Itoa(profile.QueueBytes) + "b"
	rootDelete := networkCommand("tc", "qdisc", "del", "dev", device, "root")
	if err := lab.managed(ctx,
		networkCommand("tc", "qdisc", "add", "dev", device, "root", "handle", "1:", "tbf", "rate", rate, "burst", burst, "limit", limit),
		rootDelete,
	); err != nil {
		return err
	}
	if err := lab.managed(ctx,
		networkCommand("ip", "link", "add", "name", ifb, "type", "ifb"),
		networkCommand("ip", "link", "del", "dev", ifb),
	); err != nil {
		return err
	}
	if err := lab.run(ctx, networkCommand("ip", "link", "set", "dev", ifb, "mtu", mtu, "up")); err != nil {
		return err
	}
	if err := lab.managed(ctx,
		networkCommand("tc", "qdisc", "add", "dev", ifb, "root", "handle", "20:", "fq", "nopacing", "limit", "65535", "flow_limit", "65535"),
		networkCommand("tc", "qdisc", "del", "dev", ifb, "root"),
	); err != nil {
		return err
	}
	duplicateIfIndex := 0
	if profile.DuplicatePercent > 0 {
		resolver, ok := lab.runner.(interfaceIndexResolver)
		if !ok {
			return errors.New("duplicate injection requires an IFB interface index resolver")
		}
		resolvedIndex, err := resolver.InterfaceIndex(ctx, namespace, ifb)
		if err != nil {
			return fmt.Errorf("resolve duplicate IFB %s in %s: %w", ifb, namespace, err)
		}
		duplicateIfIndex = resolvedIndex
	}
	encoded, err := encodeFaultConfig(profile, duplicateIfIndex)
	if err != nil {
		return err
	}
	updateArgs := []string{"map", "update", "pinned", configMap, "key", "hex", "00", "00", "00", "00", "value", "hex"}
	updateArgs = append(updateArgs, byteArguments(encoded)...)
	if err := lab.run(ctx, command{bpfTool, updateArgs}); err != nil {
		return err
	}
	clsactDelete := networkCommand("tc", "qdisc", "del", "dev", device, "clsact")
	if err := lab.managed(ctx,
		networkCommand("tc", "qdisc", "add", "dev", device, "clsact"),
		clsactDelete,
	); err != nil {
		return err
	}
	if err := lab.run(ctx, networkCommand("tc", "filter", "add", "dev", device, "ingress", "pref", "10", "protocol", "all", "bpf", "direct-action", "object-pinned", program)); err != nil {
		return err
	}
	return lab.run(ctx, networkCommand("tc", "filter", "add", "dev", device, "ingress", "pref", "20", "protocol", "all", "matchall", "action", "mirred", "egress", "redirect", "dev", ifb))
}

func (lab *Lab) managed(ctx context.Context, setup, cleanup command) error {
	if err := lab.run(ctx, setup); err != nil {
		return err
	}
	lab.addCleanup(cleanup)
	return nil
}

func (lab *Lab) addCleanup(value command) {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	lab.cleanup = append(lab.cleanup, value)
	lab.closed = false
}

type interfaceIndexResolver interface {
	InterfaceIndex(context.Context, string, string) (int, error)
}

func validateFaultProfile(profile FaultProfile) error {
	if profile.LinkMTU < 1280 || profile.LinkMTU > 9000 {
		return errors.New("fault profile is outside the frozen network bounds")
	}
	if profile.LossMode == LossNone {
		if profile.BaseDelay != 0 || len(profile.Jitter) != 1 || profile.Jitter[0] != 0 || profile.RateBitsPerSecond != 0 ||
			profile.TokenBurstBytes != 0 || profile.QueueBytes != 0 || profile.EveryNth != 0 || profile.BlockSize != 0 ||
			profile.BurstFirst != 0 || profile.BurstLast != 0 || profile.ReorderPercent != 0 || profile.DuplicatePercent != 0 ||
			profile.OutageStart != 0 || profile.OutageDuration != 0 || profile.ReorderDelay != 0 {
			return errors.New("counter-only profile must not inject or shape traffic")
		}
		return nil
	}
	if profile.BaseDelay <= 0 || len(profile.Jitter) != 8 || profile.RateBitsPerSecond < 1 ||
		profile.TokenBurstBytes < 1 || profile.QueueBytes < profile.TokenBurstBytes {
		return errors.New("fault profile is outside the frozen network bounds")
	}
	for _, jitter := range profile.Jitter {
		if profile.BaseDelay+jitter < 0 {
			return errors.New("fault profile has negative effective delay")
		}
	}
	switch profile.LossMode {
	case LossPeriodic:
		if profile.EveryNth < 2 || profile.BlockSize != 0 || profile.BurstFirst != 0 || profile.BurstLast != 0 {
			return errors.New("invalid periodic loss profile")
		}
	case LossBurst:
		if profile.EveryNth != 0 || profile.BlockSize < 1 || profile.BurstFirst < 1 || profile.BurstLast < profile.BurstFirst || profile.BurstLast > profile.BlockSize {
			return errors.New("invalid burst loss profile")
		}
	default:
		return errors.New("unknown fault loss mode")
	}
	if !frozenFaultPercent(profile.ReorderPercent) || !frozenFaultPercent(profile.DuplicatePercent) {
		return errors.New("fault percentages are outside the frozen matrix")
	}
	if profile.ReorderPercent == 0 && profile.ReorderDelay != 0 || profile.ReorderPercent > 0 && profile.ReorderDelay <= 0 {
		return errors.New("reorder delay does not match the frozen matrix")
	}
	if profile.OutageStart == 0 && profile.OutageDuration == 0 {
		return nil
	}
	if profile.OutageStart != time.Second || profile.OutageDuration != 2*time.Second {
		return errors.New("outage schedule is outside the frozen matrix")
	}
	return nil
}

func frozenFaultPercent(value int) bool {
	return value == 0 || value == 1 || value == 2
}

func encodeFaultConfig(profile FaultProfile, duplicateIfIndex int) ([]byte, error) {
	if err := validateFaultProfile(profile); err != nil {
		return nil, err
	}
	if profile.DuplicatePercent > 0 && duplicateIfIndex <= 0 || profile.DuplicatePercent == 0 && duplicateIfIndex != 0 {
		return nil, errors.New("duplicate IFB index does not match the frozen matrix")
	}
	lossMode := uint32(0)
	if profile.LossMode == LossPeriodic {
		lossMode = 1
	} else if profile.LossMode == LossBurst {
		lossMode = 2
	}
	encoded := make([]byte, 144)
	binary.LittleEndian.PutUint64(encoded[0:8], uint64(profile.BaseDelay))
	for index, jitter := range profile.Jitter {
		binary.LittleEndian.PutUint64(encoded[8+index*8:16+index*8], uint64(int64(jitter)))
	}
	binary.LittleEndian.PutUint32(encoded[72:76], uint32(len(profile.Jitter)))
	binary.LittleEndian.PutUint32(encoded[76:80], lossMode)
	binary.LittleEndian.PutUint32(encoded[80:84], uint32(profile.EveryNth))
	binary.LittleEndian.PutUint32(encoded[84:88], uint32(profile.BlockSize))
	binary.LittleEndian.PutUint32(encoded[88:92], uint32(profile.BurstFirst))
	binary.LittleEndian.PutUint32(encoded[92:96], uint32(profile.BurstLast))
	binary.LittleEndian.PutUint32(encoded[96:100], uint32(profile.LinkMTU))
	binary.LittleEndian.PutUint32(encoded[104:108], uint32(profile.ReorderPercent*100))
	binary.LittleEndian.PutUint32(encoded[108:112], uint32(profile.DuplicatePercent*100))
	binary.LittleEndian.PutUint64(encoded[112:120], uint64(profile.OutageStart))
	binary.LittleEndian.PutUint64(encoded[120:128], uint64(profile.OutageDuration))
	binary.LittleEndian.PutUint64(encoded[128:136], uint64(profile.ReorderDelay))
	binary.LittleEndian.PutUint32(encoded[136:140], uint32(duplicateIfIndex))
	return encoded, nil
}

func verifiedBPFObject(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", errors.New("BPF object path must be absolute")
	}
	linkInfo, err := os.Lstat(clean)
	if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return "", errors.New("BPF object must be an existing non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", errors.New("BPF object must be an existing non-symlink file")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("BPF object must be a regular file")
	}
	return resolved, nil
}

func ReadVerifiedBPFObject(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, errors.New("BPF object path must be absolute")
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, errors.New("BPF object must be an existing non-symlink file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, errors.New("BPF object must be a regular file")
	}
	pathInfo, err := os.Lstat(clean)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return nil, errors.New("BPF object path changed while it was opened")
	}
	const maxBPFObjectBytes = 16 << 20
	value, err := io.ReadAll(io.LimitReader(file, maxBPFObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read BPF object: %w", err)
	}
	if len(value) == 0 || len(value) > maxBPFObjectBytes {
		return nil, errors.New("BPF object size is outside the release bound")
	}
	return value, nil
}

func byteArguments(value []byte) []string {
	result := make([]string, len(value))
	for index, item := range value {
		result[index] = fmt.Sprintf("%02x", item)
	}
	return result
}
