package linuxnetlab

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const FrozenFirewall = "allow-test-tcp-udp-return-icmp-ptb-only-v1"

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type Config struct {
	ClientNamespace string
	ServerNamespace string
	ClientInterface string
	ServerInterface string
	ClientAddress   netip.Prefix
	ServerAddress   netip.Prefix
	LinkMTU         int
	Firewall        string
}

type Lab struct {
	runner  CommandRunner
	config  Config
	mu      sync.Mutex
	cleanup []command
	closed  bool
}

type command struct {
	name string
	args []string
}

type step struct {
	do   command
	undo *command
}

func ConfigForCell(cellID string, run int, linkMTU int, firewall string) (Config, error) {
	if run < 1 || run > 9999 || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(cellID) {
		return Config{}, errors.New("cell id and run must identify one release workload")
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(cellID + ":" + strconv.Itoa(run)))
	slot := int(hash.Sum32() % 16384)
	third := slot / 64
	fourth := (slot % 64) * 4
	clientPrefix := netip.MustParsePrefix(fmt.Sprintf("198.18.%d.%d/30", third, fourth+1))
	serverPrefix := netip.MustParsePrefix(fmt.Sprintf("198.18.%d.%d/30", third, fourth+2))
	stem := fmt.Sprintf("fs%08x", hash.Sum32())
	return Config{
		ClientNamespace: "fc-" + stem[2:10], ServerNamespace: "fs-" + stem[2:10],
		ClientInterface: stem[:10] + "c", ServerInterface: stem[:10] + "s",
		ClientAddress: clientPrefix, ServerAddress: serverPrefix, LinkMTU: linkMTU, Firewall: firewall,
	}, nil
}

func Open(ctx context.Context, runner CommandRunner, config Config) (*Lab, error) {
	return open(ctx, runner, config, 10*time.Second)
}

func open(ctx context.Context, runner CommandRunner, config Config, rollbackTimeout time.Duration) (*Lab, error) {
	if runner == nil {
		return nil, errors.New("linux netlab command runner is required")
	}
	if rollbackTimeout <= 0 {
		return nil, errors.New("linux netlab rollback timeout must be positive")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	lab := &Lab{runner: runner, config: config}
	steps := []step{
		{command{"ip", []string{"netns", "add", config.ClientNamespace}}, &command{"ip", []string{"netns", "del", config.ClientNamespace}}},
		{command{"ip", []string{"netns", "add", config.ServerNamespace}}, &command{"ip", []string{"netns", "del", config.ServerNamespace}}},
		{command{"ip", []string{"link", "add", "name", config.ClientInterface, "netns", config.ClientNamespace, "type", "veth", "peer", "name", config.ServerInterface, "netns", config.ServerNamespace}}, nil},
		{command{"ip", []string{"-n", config.ClientNamespace, "link", "set", "dev", config.ClientInterface, "mtu", strconv.Itoa(config.LinkMTU)}}, nil},
		{command{"ip", []string{"-n", config.ServerNamespace, "link", "set", "dev", config.ServerInterface, "mtu", strconv.Itoa(config.LinkMTU)}}, nil},
		{command{"ip", []string{"-n", config.ClientNamespace, "addr", "add", config.ClientAddress.String(), "dev", config.ClientInterface}}, nil},
		{command{"ip", []string{"-n", config.ServerNamespace, "addr", "add", config.ServerAddress.String(), "dev", config.ServerInterface}}, nil},
		{command{"ip", []string{"-n", config.ClientNamespace, "link", "set", "dev", "lo", "up"}}, nil},
		{command{"ip", []string{"-n", config.ServerNamespace, "link", "set", "dev", "lo", "up"}}, nil},
		{command{"ip", []string{"-n", config.ClientNamespace, "link", "set", "dev", config.ClientInterface, "up"}}, nil},
		{command{"ip", []string{"-n", config.ServerNamespace, "link", "set", "dev", config.ServerInterface, "up"}}, nil},
	}
	steps = append(steps, firewallSteps(config.ClientNamespace)...)
	steps = append(steps, firewallSteps(config.ServerNamespace)...)
	for _, step := range steps {
		if err := lab.run(ctx, step.do); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
			cleanupErr := lab.rollback(cleanupCtx)
			cancel()
			if lab.hasPendingCleanup() {
				return lab, errors.Join(err, cleanupErr, errors.New("linux netlab rollback remains pending"))
			}
			return nil, errors.Join(err, cleanupErr)
		}
		if step.undo != nil {
			lab.cleanup = append(lab.cleanup, *step.undo)
		}
	}
	return lab, nil
}

func (lab *Lab) rollback(ctx context.Context) error {
	var result error
	for {
		result = errors.Join(result, lab.Close(ctx))
		if !lab.hasPendingCleanup() {
			return result
		}
		select {
		case <-ctx.Done():
			return errors.Join(result, context.Cause(ctx))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (lab *Lab) hasPendingCleanup() bool {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	return len(lab.cleanup) > 0
}

func firewallSteps(namespace string) []step {
	commands := []command{
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "table", "inet", "flowersec"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "chain", "inet", "flowersec", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "iifname", "lo", "accept"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "ct", "state", "established,related", "accept"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "meta", "l4proto", "{", "tcp", ",", "udp", "}", "accept"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "ip", "protocol", "icmp", "icmp", "type", "destination-unreachable", "accept"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "ip6", "nexthdr", "ipv6-icmp", "icmpv6", "type", "packet-too-big", "accept"}},
	}
	steps := make([]step, 0, len(commands))
	for _, value := range commands {
		steps = append(steps, step{do: value})
	}
	return steps
}

func (lab *Lab) Close(ctx context.Context) error {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if lab.closed || len(lab.cleanup) == 0 {
		lab.closed = true
		return nil
	}
	var result error
	remaining := make([]command, 0, len(lab.cleanup))
	for index := len(lab.cleanup) - 1; index >= 0; index-- {
		if err := lab.run(ctx, lab.cleanup[index]); err != nil {
			result = errors.Join(result, err)
			remaining = append(remaining, lab.cleanup[index])
		}
	}
	for left, right := 0, len(remaining)-1; left < right; left, right = left+1, right-1 {
		remaining[left], remaining[right] = remaining[right], remaining[left]
	}
	lab.cleanup = remaining
	lab.closed = len(lab.cleanup) == 0
	return result
}

func (lab *Lab) run(ctx context.Context, value command) error {
	if err := lab.runner.Run(ctx, value.name, value.args...); err != nil {
		return fmt.Errorf("%s %v: %w", value.name, value.args, err)
	}
	return nil
}

func validateConfig(config Config) error {
	if !identifierPattern.MatchString(config.ClientNamespace) || !identifierPattern.MatchString(config.ServerNamespace) ||
		!identifierPattern.MatchString(config.ClientInterface) || !identifierPattern.MatchString(config.ServerInterface) ||
		config.ClientNamespace == config.ServerNamespace || config.ClientInterface == config.ServerInterface ||
		!config.ClientAddress.IsValid() || !config.ServerAddress.IsValid() ||
		config.ClientAddress.Bits() != 30 || config.ServerAddress.Bits() != 30 || config.ClientAddress.Masked() != config.ServerAddress.Masked() ||
		config.ClientAddress.Addr() == config.ServerAddress.Addr() || config.LinkMTU < 1280 || config.LinkMTU > 9000 || config.Firewall != FrozenFirewall {
		return errors.New("linux netlab configuration is outside the frozen release contract")
	}
	return nil
}
