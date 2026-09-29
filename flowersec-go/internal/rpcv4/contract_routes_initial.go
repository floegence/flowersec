package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// Called before the routes escape construction. The existing bounded offer
// sets own the snapshots; no configuration slices remain attached to them.
func (r *ContractRoutes) installInitialOffers(methods []MethodRoutes) error {
	for ordinal, method := range methods {
		belongs := func(digest [32]byte) bool {
			for _, entry := range r.entries {
				if entry.method == uint32(ordinal) && entry.policy.Digest == digest {
					return true
				}
			}
			return false
		}
		for _, offer := range method.InitialOffers {
			if !belongs(offer.Digest) {
				return ErrAssociation
			}
			var buffer [256]byte
			wire, err := protocolv4.EncodeMap(buffer[:], "AdmissionOffer", []protocolv4.Field{
				{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: offer.Digest[:]},
				{Name: "not_before_ms", Number: offer.NotBeforeMS},
				{Name: "not_after_ms", Number: offer.NotAfterMS},
			})
			if err != nil {
				return err
			}
			if err := r.RegisterOffer(offer.Digest, wire); err != nil {
				return err
			}
		}
		if method.AdvertisedContract != ([32]byte{}) {
			if !belongs(method.AdvertisedContract) {
				return ErrAssociation
			}
			if err := r.Advertise(method.AdvertisedContract); err != nil {
				return err
			}
		}
	}
	return nil
}
