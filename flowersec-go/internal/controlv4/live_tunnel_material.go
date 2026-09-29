package controlv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// The application response carries only this endpoint's exact original bytes.
// Credential validation stays with the original Session owner.
func liveTunnelMaterialLimit() int {
	proof, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	grant, _ := protocolv4.SchemaByteLimit("Grant")
	return proof + grant + 64
}

func encodeLiveTunnelMaterial(dst []byte, material [2][]byte) (int, error) {
	proof, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	grant, _ := protocolv4.SchemaByteLimit("Grant")
	if len(material[0]) == 0 || len(material[0]) > proof || len(material[1]) == 0 || len(material[1]) > grant {
		return 0, resourcev4.ErrConfiguration
	}
	w := poolWireWriter{dst: dst}
	w.array(3)
	w.text("live-tunnel-material-1")
	w.blob(material[0])
	w.blob(material[1])
	return w.n, w.err
}

func decodeLiveTunnelMaterial(decoder *protocolv4.Decoder, wire []byte, dst [2][]byte) (sizes [2]int, err error) {
	if decoder == nil {
		return sizes, resourcev4.ErrConfiguration
	}
	doc, err := decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return sizes, ErrResponse
	}
	defer doc.Release()
	r := poolWireReader{}
	root := doc.Root()
	r.array(root, 3)
	if r.text(root.Index(0)) != "live-tunnel-material-1" || r.err != nil {
		return sizes, ErrResponse
	}
	var fields [2][]byte
	for i, schema := range [2]string{"ActivationAuthorization", "Grant"} {
		limit, _ := protocolv4.SchemaByteLimit(schema)
		var ok bool
		fields[i], ok = root.Index(i + 1).ByteString()
		if !ok || len(fields[i]) == 0 || len(fields[i]) > limit || len(dst[i]) < len(fields[i]) {
			return sizes, ErrResponse
		}
	}
	for i := range fields {
		sizes[i] = copy(dst[i], fields[i])
	}
	return sizes, nil
}
