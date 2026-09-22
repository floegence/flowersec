//go:build (!amd64 && !arm64) || purego || boringcrypto || goexperiment.boringcrypto

package cryptov4

const engineResourceAssembly = false
