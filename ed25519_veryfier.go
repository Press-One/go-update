// ed25519 related functions copied from https://github.com/frankbraun/gosignify/blob/master/signify/signify.go

package update

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	sigbytes      = ed25519.SignatureSize
	secretbytes   = ed25519.PrivateKeySize
	publicbytes   = ed25519.PublicKeySize
	pkalg         = "Ed"
	kdfalg        = "BK"
	keynumlen     = 8
	commenthdr    = "untrusted comment: "
	commentmaxlen = 1024
	verifywith    = "verify with "
)

type pubkey struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Pubkey [publicbytes]byte
}

type sig struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Sig    [sigbytes]byte
}

func parseb64(b64 []byte) (string, []byte, []byte, error) {
	lines := strings.SplitAfterN(string(b64), "\n", 3)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], commenthdr) {
		return "", nil, nil, fmt.Errorf("invalid comments; must start with '%s'", commenthdr)
	}
	comment := strings.TrimSuffix(lines[0], "\n")
	if len(comment) >= commentmaxlen {
		return "", nil, nil, errors.New("comment too long") // for compatibility
	}
	comment = strings.TrimPrefix(comment, commenthdr)
	if !strings.HasSuffix(lines[1], "\n") {
		return "", nil, nil, fmt.Errorf("missing new line after base64")
	}
	enc := strings.TrimSuffix(lines[1], "\n")
	buf, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid base64 encoding in")
	}
	if len(buf) < 2 || string(buf[:2]) != pkalg {
		return "", nil, nil, fmt.Errorf("unsupported file")
	}
	var msg []byte
	if len(lines) == 3 {
		msg = []byte(lines[2])
	}
	return comment, buf, msg, nil
}

// NewED25519Verifier returns a Verifier that uses the ed25519 algorithm to verify updates.
// Compatible with signify-openbsd (embedded)
func NewED25519Verifier() Verifier {
	return verifyFn(func(checksum /*sha256*/, signature []byte, _ crypto.Hash, publicKey crypto.PublicKey) error {
		var (
			sig    sig
			pubkey pubkey
		)
		key, ok := publicKey.([]byte)
		if !ok {
			return errors.New("not a valid ed25519 public key")
		}
		_, pubkeybuf, _, err := parseb64(key)
		if err != nil {
			return err
		}
		if err := binary.Read(bytes.NewReader(pubkeybuf), binary.BigEndian, &pubkey); err != nil {
			return err
		}

		_, sigbuf, msg, err := parseb64(signature)
		if err != nil {
			return err
		}
		if err := binary.Read(bytes.NewReader(sigbuf), binary.BigEndian, &sig); err != nil {
			return err
		}

		if !bytes.Equal(pubkey.Keynum[:], sig.Keynum[:]) {
			return errors.New("verification failed: checked against wrong key")
		}
		if !ed25519.Verify(pubkey.Pubkey[:], msg, sig.Sig[:]) {
			return errors.New("signature verification failed")
		}

		msgv := strings.Split(string(msg), " = ")
		if len(msgv) != 2 {
			return errors.New("signature verification failed: invalid messages")
		}
		hash := strings.TrimSpace(msgv[1])
		if !(hex.EncodeToString(checksum) == hash) {
			return errors.New("signature verification failed: sha256 mismatch")
		}
		return nil
	})
}
