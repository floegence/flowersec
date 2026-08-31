package performance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/transporttest/linuxnetlab"
)

func supportedLinuxRunnerArchitecture(goos, goarch string) bool {
	return goos == "linux" && (goarch == "amd64" || goarch == "arm64")
}

func nativeStreamID(stream carrier.Stream) int64 {
	if identified, ok := stream.(interface{ NativeStreamID() int64 }); ok {
		return identified.NativeStreamID()
	}
	return -1
}

func browserCapacityWorkerCommand(ctx context.Context, namespace, executable string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/var/run/netns/"+namespace, "--", executable, "-test.run=^TestBrowserCapacityWorkerProcess$")
	command.Env = append(os.Environ(), "FLOWERSEC_BROWSER_CAPACITY_WORKER=1")
	configureBrowserWorkerCommand(command)
	return command
}

func runBrowserWorkerWithContext(ctx context.Context, input io.Reader, output io.Writer) error {
	if ctx == nil {
		return errors.New("browser worker context is required")
	}
	var request browserWorkerRequest
	decoder := json.NewDecoder(io.LimitReader(input, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("browser capacity worker request is invalid")
	}
	if request.Mode != "capacity" || request.Capacity == nil {
		return errors.New("browser worker only supports explicit capacity runs")
	}
	if err := linuxnetlab.RequireCurrentNamespace(request.ClientNamespace); err != nil {
		return err
	}
	return runBrowserCapacityWorker(ctx, request, output)
}

func startBrowserArtifactHTTPServer(namespace, address string, handler http.Handler) (net.Listener, *http.Server, string, error) {
	var listener net.Listener
	if err := linuxnetlab.InNamespace(namespace, func() error {
		var err error
		listener, err = net.Listen("tcp4", net.JoinHostPort(address, "0"))
		return err
	}); err != nil {
		return nil, nil, "", err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, server, "http://" + net.JoinHostPort(address, fmt.Sprint(port)) + "/artifacts", nil
}

func closeBrowserArtifactHTTPServer(server *http.Server, listener net.Listener) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(ctx)
	listenerErr := listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(shutdownErr, listenerErr)
}
