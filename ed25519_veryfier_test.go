package update

import (
	"bytes"
	"testing"
)

// key generated with signify
const ed25519PublicKey = `untrusted comment: signify public key
RWTmy5Eqf67hzAZOvgvJZhsk9gBT1o5NMNGvqDVp61T+upfZMZIyorMa
`

// echo -n -e "\x01\x02\x03\x04\x05\x06" > TestVerifyED25519ignature
// signify -S -s ./newkey.sec  -m ./TestVerifyED25519ignature
const signature = `untrusted comment: verify with newkey.pub
RWTmy5Eqf67hzOUnbZIdeRoaGdxQ+7K7DKFuyRSkHhcXDgOq39zSMiWb1pjLdbInhjPp8k8Z6NmO42jO+ocQ1SMcY0STv8AXog0=
`

func TestVerifyED25519ignature(t *testing.T) {
	fName := "TestVerifyED25519ignature"
	defer cleanup(fName)
	writeOldFile(fName, t)

	opts := Options{
		TargetPath:       fName,
		Verifier:         NewED25519Verifier(),
		VerifyUseContent: true,
		PublicKey:        []byte(ed25519PublicKey),
		Signature:        []byte(signature),
	}

	err := Apply(bytes.NewReader(newFile), opts)
	validateUpdate(fName, err, t)
}
