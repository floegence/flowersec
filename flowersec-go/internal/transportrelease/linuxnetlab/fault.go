package linuxnetlab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	LossPeriodic = "periodic"
	LossBurst    = "burst"

	bpfPinRoot = "/sys/fs/bpf"
	bpfTool    = "/opt/host-linux-tools/bpftool"
)

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
}

func (lab *Lab) ApplyFaultProfile(ctx context.Context, profile FaultProfile) (resultErr error) {
	encoded, err := encodeFaultConfig(profile)
	if err != nil {
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
		if err := lab.applyDirection(ctx, labDirectory, object, encoded, profile, direction.name, direction.namespace, direction.device); err != nil {
			return err
		}
	}
	return nil
}

func (lab *Lab) applyDirection(ctx context.Context, labDirectory, object string, encoded []byte, profile FaultProfile, name, namespace, device string) error {
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
	updateArgs := []string{"map", "update", "pinned", configMap, "key", "hex", "00", "00", "00", "00", "value", "hex"}
	updateArgs = append(updateArgs, byteArguments(encoded)...)
	if err := lab.run(ctx, command{bpfTool, updateArgs}); err != nil {
		return err
	}
	networkCommand := func(args ...string) command {
		return command{"nsenter", append([]string{"--net=/var/run/netns/" + namespace, "--"}, args...)}
	}
	ifb := device + "i"
	mtu := strconv.Itoa(profile.LinkMTU)
	if err := lab.run(ctx, networkCommand(
		"ip", "link", "set", "dev", device,
		"gso_max_segs", "1", "gso_max_size", mtu, "gro_max_size", mtu,
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

func encodeFaultConfig(profile FaultProfile) ([]byte, error) {
	if profile.BaseDelay <= 0 || len(profile.Jitter) != 8 || profile.RateBitsPerSecond < 1 ||
		profile.TokenBurstBytes < 1 || profile.QueueBytes < profile.TokenBurstBytes || profile.LinkMTU < 1280 || profile.LinkMTU > 9000 {
		return nil, errors.New("fault profile is outside the frozen network bounds")
	}
	for _, jitter := range profile.Jitter {
		if profile.BaseDelay+jitter < 0 {
			return nil, errors.New("fault profile has negative effective delay")
		}
	}
	lossMode := uint32(0)
	switch profile.LossMode {
	case LossPeriodic:
		if profile.EveryNth < 2 || profile.BlockSize != 0 || profile.BurstFirst != 0 || profile.BurstLast != 0 {
			return nil, errors.New("invalid periodic loss profile")
		}
		lossMode = 1
	case LossBurst:
		if profile.EveryNth != 0 || profile.BlockSize < 1 || profile.BurstFirst < 1 || profile.BurstLast < profile.BurstFirst || profile.BurstLast > profile.BlockSize {
			return nil, errors.New("invalid burst loss profile")
		}
		lossMode = 2
	default:
		return nil, errors.New("unknown fault loss mode")
	}
	encoded := make([]byte, 104)
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

func byteArguments(value []byte) []string {
	result := make([]string, len(value))
	for index, item := range value {
		result[index] = fmt.Sprintf("%02x", item)
	}
	return result
}
