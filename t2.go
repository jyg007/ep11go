package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)


func domainMaskUint32(domain int) []byte {
	mask := uint32(1 << domain)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, mask)

	return b
}

// build inner TLV: [type][id][data]
func buildTLV(t uint16, id uint32, data []byte) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, t)
	_ = binary.Write(buf, binary.BigEndian, id)
	buf.Write(data)
	return buf.Bytes()
}

// ASN.1 length encoding (simple form)
func encLen(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	}
	// simplified long form
	b := []byte{byte(0x80 | 4)}
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(l))
	return append(b, tmp...)
}

// wrap OCTET STRING
func octetString(data []byte) []byte {
	return append(append([]byte{0x04}, encLen(len(data))...), data...)
}

// wrap SEQUENCE
func sequence(items [][]byte) []byte {
	var body bytes.Buffer
	for _, i := range items {
		body.Write(i)
	}
	return append(append([]byte{0x30}, encLen(body.Len())...), body.Bytes()...)
}

func main() {
/*
	hexCerts := []string{
		"30820309308201f1a00302010202145943fbe20fcae240ccd02adb1bf4fdb37990e2ba300d06092a864886f70d01010b050030143112301006035504030c0944756d6d79204b5048301e170d3236303632353130333434315a170d3237303632353130333434315a30143112301006035504030c0944756d6d79204b504830820122300d06092a864886f70d01010105000382010f003082010a0282010100c45c6c9d83ad84c56c4686b8c54136a54e6b30f3097e70358653d940d086642136941c9ef577229c3f5aadd32b6d68b5dcd51beefe7a33b6625718e00ed3c3b2ed504998b403977210ec10ed7d7da886b3a963822ae5900306b2d28bc2c9453bc0a27447b2887f781d6426029a4b2ba0f965cef3a2b3aea6ddd47db441c42fb771e542278923e9562bd2be2b662f83657b385b10e7446fa001937a846b3611dc67682eca8a14f037108174ddebea3d1260e5abc3c5b2fa5dbde905c0d41ab5a8f165fb0597a7d704019bd097c9cb2d6d11637612308b34f61545e17a8a88b08a1637fa2f5fe09d8e90339bd6eaf0fc151ba14b5baf0ba91074d692ecba8e80830203010001a3533051301d0603551d0e04160414651d56a8d2b60c56db9d5150e08952b6184b2a57301f0603551d23041830168014651d56a8d2b60c56db9d5150e08952b6184b2a57300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100aa80cd1b92f419b3849c00eaff30da705527c43b36ebea4189a79e25ed9e54e82919b78a53f67c3aad39144bc19e1ae4e792cf9469608923b609592ad349fac1e4cb7dc05d63fe9a758b95f6381617b3f008f5439eea1e6d79577ab0d1c8f5219b54fd21d60d2f393983b1513871c01c16d46615771484c7ab5d37c1b0b2246e5b9c32c19c221926b86b95edc08ddc32a6b4bb1eab3967bf5ec97a8de1f803270b6673b88f4d36918bff08c661e743269a500134fd06ec90c77e6a400fad41b2439fa51ac00212fbafdf4f562a91eac6c01dec594c29457e1113ca759b9959a6d72419eb55ae5278eb2f7cfd8ab926bc474d011cf6a5ba591d43419196d0e836",
	}
*/
	hexCerts := []string{
"30820222300d06092a864886f70d01010105000382020f003082020a0282020100b7c6d25dae761f87d90017edef1f40b2637276518e3df05dcb51c0d601b498a799fa29580a4d8a7cb7646574ece6be1e07d0ff069cc8cf9b9f27e878d37ade9d80b0a988b77ff65142fdc5d3d1767282f54696b49ed5a06009d3e8b6108520896bd4198a4a081a39e85c20bcd9721f6709d7eb941bb6fd303edd36fc4af68073795648751d3fdc8ac1b918eef1e3f11d4630aefe140673409abd60fac1ae33ab57d345e19733b1c7db570769e1ba54d28d03703c73eb8eccf0f208065742640c3e117344527b7a0477814d1bba349653f20fa6da58daa76112cf159f104c9fb273aa36a604d83e2ee096a2b6825913a9552c26e73302c41cb68af7cb867b85726b2881dab3a3102617068399ac360fe99f0fa6e5bc907a852680cffa233f33ac112ae0128ddd85cb0ea169f05ce0b152fca8acbfeb2bdeef515e2607366477845b758455a4af91e04f3601cd3679123526ffbea0b7a5152a6c4f014fb26d7118b2ea3beaea5501776cd2e556c9e8c74aa95178c24847d988c10b4ed62f663eb69f6133937b869295fa102e3d6c659f90ae39540301e65cf767dc579ff8510660d7fec7cee40cfb6df77431d76211637aea53b08113454a37ab2be36845bf34e5d13bfb9558928c9b85b1c55263adf05b93debcfab1e67a4f2730c8588ba76b33dc7afb1e9c408ae86e0e45b1e9ee9468fc7f1e1828a517747e6947208f180e810203010001",
}
	var certs bytes.Buffer

	for _, h := range hexCerts {
		b, _ := hex.DecodeString(h)
		certs.Write(b)
	}

	// x001C = number of KPHs
	x001C := octetString(buildTLV(0x001C, 0x00000001, []byte{}))

	// x001D = certs
	x001D := octetString(buildTLV(0x001D, 0x00000000, certs.Bytes()))
        x0003 := octetString(buildTLV(0x0003, 0x00008000, []byte{}))
//        x0003 := octetString(buildTLV(0x0003, 0x00000000, []byte{0x00,0x00, 0x80, 0x00}))
        x001F := octetString(buildTLV(0x001F, 0x00000001, []byte{}))

	// full module state SEQUENCE
	out := sequence([][]byte{
		x001C,
		x001D,
                x0003,
		x001F,
	})

	fmt.Printf("%X\n", out)
}
