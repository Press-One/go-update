package update

import (
	"bytes"
	"crypto"
	"io/ioutil"
	"testing"
)

// key generated with signify
const ed25519PublicKey = `untrusted comment: signify public key
RWRE33s/ZBRMI7egZoTfmDQaDeTEGN68Mo0zOaSt6XppleuYaeK1VGH1
`

// shasum -a 256 TestVerifyED25519ignature | awk '{print "SHA256 ("$2") = "$1}' > hash
// signify -S -e -s key.sec -m hash -x TestVerifyED25519ignature.sig
const signature = `untrusted comment: verify with key.pub
RWRE33s/ZBRMI85CRsh+BN9J/pJIoW+khF2GdYFvt5nxY8GRoaH1G9WTL60aFXEBQDK1f0WxvBhu1+rFMvOnKvZSAt5rVx/mCA4=
SHA256 (TestVerifyED25519ignature) = 7192385c3c0605de55bb9476ce1d90748190ecb32a8eed7f5207b30cf6a1fe89
`

func TestVerifyED25519ignature(t *testing.T) {
	fName := "TestVerifyED25519ignature"
	defer cleanup(fName)
	writeOldFile(fName, t)

	opts := Options{
		TargetPath:       fName,
		Verifier:         NewED25519Verifier(),
		VerifyUseContent: false,
		PublicKey:        []byte(ed25519PublicKey),
		Signature:        []byte(signature),
		Hash:             crypto.SHA256,
	}

	err := Apply(bytes.NewReader(newFile), opts)
	validateUpdate(fName, err, t)
}

func TestUnZip(t *testing.T) {
	content, _ := ioutil.ReadFile("test/newFile.zip") // the file is inside the local directory
	uncompressedBytes, _ := extractZip(content)
	if !bytes.Equal(uncompressedBytes, newFile) {
		t.Fatalf("Unzip Failed")
	}
}

func TestUnTarGz(t *testing.T) {
	content, _ := ioutil.ReadFile("test/newFile.tar.gz") // the file is inside the local directory
	uncompressedBytes, _ := extractTarGz(content)
	if !bytes.Equal(uncompressedBytes, newFile) {
		t.Fatalf("UnTarGz Failed")
	}
}
