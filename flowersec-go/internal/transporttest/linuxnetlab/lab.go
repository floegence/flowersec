package linuxnetlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os"
	"path/filepath"
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
	ClientNamespace       string
	ServerNamespace       string
	RouterNamespace       string
	ClientInterface       string
	ServerInterface       string
	RouterClientInterface string
	RouterServerInterface string
	ClientAddress         netip.Prefix
	ServerAddress         netip.Prefix
	RouterClientAddress   netip.Prefix
	RouterServerAddress   netip.Prefix
	LinkMTU               int
	Firewall              string
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
	return configForCellFamily(cellID, run, linkMTU, firewall, false)
}

// ConfigForTestRun derives names that are unique to one invocation while
// retaining a test-specific prefix for bounded stale-resource recovery.
func ConfigForTestRun(testID, runID string, run int, linkMTU int, firewall string) (Config, error) {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9/-]*$`).MatchString(testID) || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(runID) {
		return Config{}, errors.New("test and run IDs must be canonical")
	}
	config, err := configForCellFamily(runID, run, linkMTU, firewall, false)
	if err != nil {
		return Config{}, err
	}
	owner := resourceOwnerPrefix(testID)
	instanceHash := sha256.Sum256([]byte(runID + ":" + strconv.Itoa(run)))
	token := owner + fmt.Sprintf("%x", instanceHash[:2])
	config.ClientNamespace = "fc-" + token
	config.ServerNamespace = "fs-" + token
	config.ClientInterface = "vc" + token + "c"
	config.ServerInterface = "vs" + token + "s"
	return config, validateConfig(config)
}

func resourceOwnerPrefix(testID string) string {
	hash := sha256.Sum256([]byte(testID))
	return fmt.Sprintf("%x", hash[:3])
}

// ConfigForSystemCase derives an isolated IPv4 or IPv6 lab for one frozen
// system fault-observation case.
func ConfigForSystemCase(caseID string, run int, linkMTU int, firewall string, ipv6 bool) (Config, error) {
	return configForCellFamily(caseID, run, linkMTU, firewall, ipv6)
}

// ConfigForRoutedSystemCase derives a three-namespace path whose router
// egress MTU can change without changing either endpoint's local route MTU.
func ConfigForRoutedSystemCase(caseID string, run int, linkMTU int, firewall string, ipv6 bool) (Config, error) {
	config, err := configForCellFamily(caseID, run, linkMTU, firewall, ipv6)
	if err != nil {
		return Config{}, err
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(caseID + ":" + strconv.Itoa(run)))
	slot := int(hash.Sum32() % 16384)
	third := slot / 64
	fourth := (slot % 64) * 4
	client, routerClient := netip.MustParsePrefix(fmt.Sprintf("198.18.%d.%d/30", third, fourth+1)), netip.MustParsePrefix(fmt.Sprintf("198.18.%d.%d/30", third, fourth+2))
	routerServer, server := netip.MustParsePrefix(fmt.Sprintf("198.19.%d.%d/30", third, fourth+1)), netip.MustParsePrefix(fmt.Sprintf("198.19.%d.%d/30", third, fourth+2))
	if ipv6 {
		client = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:1::1/126", slot))
		routerClient = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:1::2/126", slot))
		routerServer = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:2::1/126", slot))
		server = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x:2::2/126", slot))
	}
	stem := fmt.Sprintf("fs%08x", hash.Sum32())
	config.ClientAddress, config.ServerAddress = client, server
	config.RouterNamespace = "fr-" + stem[2:10]
	config.RouterClientInterface, config.RouterServerInterface = stem[:10]+"rc", stem[:10]+"rs"
	config.RouterClientAddress, config.RouterServerAddress = routerClient, routerServer
	return config, nil
}

func configForCellFamily(cellID string, run int, linkMTU int, firewall string, ipv6 bool) (Config, error) {
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
	if ipv6 {
		clientPrefix = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::1/126", slot))
		serverPrefix = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::2/126", slot))
	}
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
	}
	if config.RouterNamespace == "" {
		steps = append(steps,
			step{command{"ip", []string{"link", "add", "name", config.ClientInterface, "netns", config.ClientNamespace, "type", "veth", "peer", "name", config.ServerInterface, "netns", config.ServerNamespace}}, nil},
			step{command{"ip", []string{"-n", config.ClientNamespace, "link", "set", "dev", config.ClientInterface, "mtu", strconv.Itoa(config.LinkMTU)}}, nil},
			step{command{"ip", []string{"-n", config.ServerNamespace, "link", "set", "dev", config.ServerInterface, "mtu", strconv.Itoa(config.LinkMTU)}}, nil},
			step{command{"ip", addressAddArguments(config.ClientNamespace, config.ClientAddress, config.ClientInterface)}, nil},
			step{command{"ip", addressAddArguments(config.ServerNamespace, config.ServerAddress, config.ServerInterface)}, nil},
		)
	} else {
		steps = append(steps,
			step{command{"ip", []string{"netns", "add", config.RouterNamespace}}, &command{"ip", []string{"netns", "del", config.RouterNamespace}}},
			step{command{"ip", []string{"link", "add", "name", config.ClientInterface, "netns", config.ClientNamespace, "type", "veth", "peer", "name", config.RouterClientInterface, "netns", config.RouterNamespace}}, nil},
			step{command{"ip", []string{"link", "add", "name", config.RouterServerInterface, "netns", config.RouterNamespace, "type", "veth", "peer", "name", config.ServerInterface, "netns", config.ServerNamespace}}, nil},
		)
		for _, item := range []struct{ namespace, device string }{
			{config.ClientNamespace, config.ClientInterface}, {config.RouterNamespace, config.RouterClientInterface},
			{config.RouterNamespace, config.RouterServerInterface}, {config.ServerNamespace, config.ServerInterface},
		} {
			steps = append(steps, step{command{"ip", []string{"-n", item.namespace, "link", "set", "dev", item.device, "mtu", strconv.Itoa(config.LinkMTU)}}, nil})
		}
		for _, item := range []struct{ namespace, device, address string }{
			{config.ClientNamespace, config.ClientInterface, config.ClientAddress.String()},
			{config.RouterNamespace, config.RouterClientInterface, config.RouterClientAddress.String()},
			{config.RouterNamespace, config.RouterServerInterface, config.RouterServerAddress.String()},
			{config.ServerNamespace, config.ServerInterface, config.ServerAddress.String()},
		} {
			address := netip.MustParsePrefix(item.address)
			steps = append(steps, step{command{"ip", addressAddArguments(item.namespace, address, item.device)}, nil})
		}
	}
	for _, item := range []struct{ namespace, device string }{{config.ClientNamespace, config.ClientInterface}, {config.ServerNamespace, config.ServerInterface}} {
		steps = append(steps, step{command{"ip", []string{"-n", item.namespace, "link", "set", "dev", "lo", "up"}}, nil},
			step{command{"ip", []string{"-n", item.namespace, "link", "set", "dev", item.device, "up"}}, nil})
	}
	if config.RouterNamespace != "" {
		steps = append(steps,
			step{command{"ip", []string{"-n", config.RouterNamespace, "link", "set", "dev", "lo", "up"}}, nil},
			step{command{"ip", []string{"-n", config.RouterNamespace, "link", "set", "dev", config.RouterClientInterface, "up"}}, nil},
			step{command{"ip", []string{"-n", config.RouterNamespace, "link", "set", "dev", config.RouterServerInterface, "up"}}, nil},
			step{command{"ip", []string{"-n", config.ClientNamespace, "route", "add", config.ServerAddress.Masked().String(), "via", config.RouterClientAddress.Addr().String()}}, nil},
			step{command{"ip", []string{"-n", config.ServerNamespace, "route", "add", config.ClientAddress.Masked().String(), "via", config.RouterServerAddress.Addr().String()}}, nil},
		)
		forwardKey := "net.ipv4.ip_forward=1"
		if config.ClientAddress.Addr().Is6() {
			forwardKey = "net.ipv6.conf.all.forwarding=1"
		}
		steps = append(steps, step{command{"ip", []string{"netns", "exec", config.RouterNamespace, "sysctl", "-q", "-w", forwardKey}}, nil})
	}
	steps = append(steps, firewallSteps(config.ClientNamespace)...)
	steps = append(steps, firewallSteps(config.ServerNamespace)...)
	if config.RouterNamespace != "" {
		steps = append(steps, routerFirewallSteps(config.RouterNamespace)...)
	}
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

func addressAddArguments(namespace string, address netip.Prefix, device string) []string {
	arguments := []string{"-n", namespace, "addr", "add", address.String(), "dev", device}
	if address.Addr().Is6() {
		arguments = append(arguments, "nodad")
	}
	return arguments
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
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "ip6", "nexthdr", "ipv6-icmp", "icmpv6", "type", "{", "133", ",", "134", ",", "135", ",", "136", "}", "accept"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "input", "ip6", "nexthdr", "ipv6-icmp", "icmpv6", "type", "packet-too-big", "accept"}},
	}
	steps := make([]step, 0, len(commands))
	for _, value := range commands {
		steps = append(steps, step{do: value})
	}
	return steps
}

func routerFirewallSteps(namespace string) []step {
	commands := []command{
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "table", "inet", "flowersec"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "chain", "inet", "flowersec", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "drop", ";", "}"}},
		{"ip", []string{"netns", "exec", namespace, "nft", "add", "rule", "inet", "flowersec", "forward", "meta", "l4proto", "{", "tcp", ",", "udp", ",", "icmp", ",", "ipv6-icmp", "}", "accept"}},
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
		return lab.verifyRemoved()
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
	if len(lab.cleanup) == 0 {
		result = errors.Join(result, lab.verifyRemoved())
	}
	return result
}

func (lab *Lab) verifyRemoved() error {
	paths := []string{
		filepath.Join("/var/run/netns", lab.config.ClientNamespace),
		filepath.Join("/var/run/netns", lab.config.ServerNamespace),
		filepath.Join(bpfPinRoot, "flowersec-"+lab.config.ClientNamespace+"-"+lab.config.ServerNamespace),
	}
	if lab.config.RouterNamespace != "" {
		paths = append(paths, filepath.Join("/var/run/netns", lab.config.RouterNamespace))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("linux netlab resource remains after cleanup: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("verify linux netlab cleanup %s: %w", path, err)
		}
	}
	return nil
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
		len(config.ClientInterface+"i") > 15 || len(config.ServerInterface+"i") > 15 ||
		config.ClientNamespace == config.ServerNamespace || config.ClientInterface == config.ServerInterface ||
		!config.ClientAddress.IsValid() || !config.ServerAddress.IsValid() ||
		config.ClientAddress.Addr().Is4() != config.ServerAddress.Addr().Is4() ||
		config.ClientAddress.Bits() != config.ServerAddress.Bits() ||
		config.ClientAddress.Addr().Is4() && config.ClientAddress.Bits() != 30 ||
		config.ClientAddress.Addr().Is6() && config.ClientAddress.Bits() != 126 ||
		config.ClientAddress.Addr() == config.ServerAddress.Addr() || config.LinkMTU < 1280 || config.LinkMTU > 9000 || config.Firewall != FrozenFirewall {
		return errors.New("linux netlab configuration is outside the frozen release contract")
	}
	if config.RouterNamespace == "" {
		if config.ClientAddress.Masked() != config.ServerAddress.Masked() || config.RouterClientInterface != "" || config.RouterServerInterface != "" ||
			config.RouterClientAddress.IsValid() || config.RouterServerAddress.IsValid() {
			return errors.New("direct linux netlab routing configuration is invalid")
		}
		return nil
	}
	if !identifierPattern.MatchString(config.RouterNamespace) || !identifierPattern.MatchString(config.RouterClientInterface) ||
		!identifierPattern.MatchString(config.RouterServerInterface) || config.RouterNamespace == config.ClientNamespace || config.RouterNamespace == config.ServerNamespace ||
		config.RouterClientInterface == config.RouterServerInterface || !config.RouterClientAddress.IsValid() || !config.RouterServerAddress.IsValid() ||
		config.RouterClientAddress.Addr().Is4() != config.ClientAddress.Addr().Is4() || config.RouterServerAddress.Addr().Is4() != config.ServerAddress.Addr().Is4() ||
		config.RouterClientAddress.Masked() != config.ClientAddress.Masked() || config.RouterServerAddress.Masked() != config.ServerAddress.Masked() ||
		config.ClientAddress.Masked() == config.ServerAddress.Masked() {
		return errors.New("routed linux netlab configuration is invalid")
	}
	return nil
}
