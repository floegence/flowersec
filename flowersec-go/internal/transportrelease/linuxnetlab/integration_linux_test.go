//go:build linux

package linuxnetlab

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPrivilegedTopologyLifecycle(t *testing.T) {
	if os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_LINUX_NETLAB_INTEGRATION=1 on the audited privileged Linux runner")
	}
	config, err := ConfigForCell("integration", os.Getpid()%9999+1, 1280, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lab, err := Open(ctx, ExecRunner{}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := lab.Close(cleanupCtx); err != nil {
			t.Error(err)
		}
	})
	serverScript := `import socket,sys
s=socket.socket(); s.bind((sys.argv[1],38123)); s.listen(1)
c,_=s.accept(); data=c.recv(16)
assert data == b'flowersec'; c.sendall(b'ok')`
	server := exec.CommandContext(ctx, "ip", "netns", "exec", config.ServerNamespace, "python3", "-c", serverScript, config.ServerAddress.Addr().String())
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	clientScript := `import socket,sys,time
last=None
for _ in range(40):
  try:
    s=socket.create_connection((sys.argv[1],38123),0.25); break
  except OSError as e:
    last=e; time.sleep(0.05)
else: raise last
s.sendall(b'flowersec'); assert s.recv(2) == b'ok'`
	client := exec.CommandContext(ctx, "ip", "netns", "exec", config.ClientNamespace, "python3", "-c", clientScript, config.ServerAddress.Addr().String())
	if output, err := client.CombinedOutput(); err != nil {
		t.Fatalf("client namespace cannot reach server namespace: %v: %s", err, output)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("server namespace failed: %v: %s", err, serverOutput.Bytes())
	}
	if err := lab.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{config.ClientNamespace, config.ServerNamespace} {
		if err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "true").Run(); err == nil {
			t.Fatalf("namespace %s remained after close", namespace)
		}
	}
	for _, name := range []string{config.ClientInterface, config.ServerInterface} {
		if err := exec.CommandContext(ctx, "ip", "link", "show", "dev", name).Run(); err == nil {
			t.Fatalf("veth %s remained after close", name)
		}
	}
}
