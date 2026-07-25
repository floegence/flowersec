//go:build !linux

package main

func openCollectionLaneSet(count int, _, _ bool) (collectionLaneSet, error) {
	return newLocalCollectionLaneSet(count), nil
}
