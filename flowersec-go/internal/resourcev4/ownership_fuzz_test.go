package resourcev4

import "testing"

func FuzzResourceOwnershipConservation(f *testing.F) {
	f.Add([]byte{0, 1, 8, 3, 4, 6, 2, 5})
	f.Add([]byte{0, 0, 0, 0, 1, 1, 4, 3, 6, 2, 2})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			return
		}
		limit := Vector{SDKBytes: 32, Items: 4}
		r := testRoot(t, limit, 8, 16)
		a := account(t, r, TenantAccount, 1, limit)
		var refs [16]Reference
		for step, action := range input {
			i := int(action>>4) % len(refs)
			free := -1
			for j, ref := range refs {
				if ref == (Reference{}) {
					free = j
					break
				}
			}
			switch action & 7 {
			case 0:
				if free >= 0 {
					key := owner(byte(step%255 + 1))
					key.Instance[1] = byte(step / 255)
					refs[free], _ = r.Reserve(key, Vector{SDKBytes: uint64(action%8 + 1), Items: 1}, a)
				}
			case 1:
				if free >= 0 {
					refs[free], _ = refs[i].Borrow()
				}
			case 2:
				refs[i].Release()
				refs[i].Release()
				refs[i] = Reference{}
			case 3:
				if moved, err := refs[i].Take(Vector{SDKBytes: 1}); err == nil {
					refs[i].Release() // The old copied constructor handle is stale.
					refs[i] = moved
				}
			case 4:
				if free >= 0 && refs[i].root != nil {
					s, _ := refs[i].slotsLocked() // This fuzz owner is single-threaded.
					if s != nil {
						key := s.owner
						key.Instance = [16]byte{byte(step%255 + 1), byte(step / 255), 1}
						refs[free], _ = refs[i].Transfer(key, [16]byte{byte(step%255 + 1), byte(step / 255)})
					}
				}
			case 5:
				r.Close()
			case 6:
				refs[i].Seal()
			case 7:
				_ = refs[i].Check()
			}
			if got := r.Snapshot(); !got.Limit.Contains(got.Charged) || got.Reservations > 8 || got.References > 16 {
				t.Fatal("aggregate exceeded original finite cap", got)
			}
			if usage, err := a.Usage(); err != nil || !limit.Contains(usage) {
				t.Fatal("tenant exceeded original cap", usage, err)
			}
		}
		for _, ref := range refs {
			ref.Release()
		}
	})
}
