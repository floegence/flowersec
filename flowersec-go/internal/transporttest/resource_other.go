//go:build !linux

package transporttest

func capturePlatformResources() (platformResources, error) {
	return platformResources{}, nil
}
