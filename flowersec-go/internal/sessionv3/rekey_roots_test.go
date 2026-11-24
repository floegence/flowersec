package sessionv3

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

func TestRekeyCollectionPreservesEveryDirectionalStreamReference(t *testing.T) {
	const current uint32 = 2
	const released uint32 = 3
	for layout := range 256 {
		session := &engineSession{
			controlSendEpoch: current, controlRecvEpoch: current,
			sendRoots: make(map[uint32]protocolv3.EpochRoots), recvRoots: make(map[uint32]protocolv3.EpochRoots),
			streams: make(map[uint64]*encryptedStream),
		}
		for epoch := range current + 2 {
			session.sendRoots[epoch] = protocolv3.EpochRoots{}
			session.recvRoots[epoch] = protocolv3.EpochRoots{}
		}
		refs := layout
		minimumSend, minimumReceive := current, current
		for id := uint64(1); id <= 2; id++ {
			stream := &encryptedStream{id: id}
			send, receive := uint32(refs&3), uint32((refs>>2)&3)
			refs >>= 4
			if send != released {
				stream.setSendRootEpoch(send)
				minimumSend = min(minimumSend, send)
			}
			if receive != released {
				stream.setReceiveRootEpoch(receive)
				minimumReceive = min(minimumReceive, receive)
			}
			session.registerStream(stream)
		}
		session.cleanupEpochRoots()
		for epoch := range current + 2 {
			_, sendKept := session.sendRoots[epoch]
			_, receiveKept := session.recvRoots[epoch]
			if sendKept != (epoch >= minimumSend) || receiveKept != (epoch >= minimumReceive) {
				t.Fatalf("stream layout %d, epoch %d: send kept=%t receive kept=%t, floors %d and %d", layout, epoch, sendKept, receiveKept, minimumSend, minimumReceive)
			}
		}
	}
}
