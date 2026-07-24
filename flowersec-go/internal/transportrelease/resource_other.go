//go:build !linux

package transportrelease

func capturePlatformResources() (platformResources, error) {
	return platformResources{}, nil
}
