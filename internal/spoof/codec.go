package spoof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceLen  = chacha20poly1305.NonceSizeX
	tagLen    = chacha20poly1305.Overhead
	headerLen = 14
	// CryptOverhead is the size an AEAD-encrypted spoof frame adds to the
	// inner packet (without outer IP/transport headers).
	CryptOverhead = nonceLen + tagLen + headerLen // 54 bytes

	authTagLen = 8
	// AuthOverhead is the size an authenticated-only (NoCrypt) spoof frame
	// adds to the inner packet (used when an encrypted tunnel runs on top).
	AuthOverhead = authTagLen + headerLen // 22 bytes

	typeData      = 1
	typeKeepalive = 2
	typeProbe     = 3
	typeProbeAck  = 4

	windowSize = 4096
	maxSkew    = 15 * time.Minute
)

var errAuth = errors.New("not a valid spoof frame for this tunnel")

type codec struct {
	noCrypt            bool
	macSend, macRecv   [32]byte
	send, recv         cipher.AEAD
	maskSend, maskRecv cipher.Block
	padding            int
	seq                uint64
	win                window
	now                func() time.Time

	rngMu sync.Mutex
	rng   *mrand.ChaCha8
}

func (c *codec) random(b []byte) {
	c.rngMu.Lock()
	c.rng.Read(b)
	c.rngMu.Unlock()
}

func newCodec(sendKey, recvKey []byte, padding int, noCrypt bool) (*codec, error) {
	if padding > 255 {
		padding = 255
	}
	var seed [32]byte
	rand.Read(seed[:])
	cd := &codec{
		noCrypt: noCrypt,
		padding: padding,
		seq:     uint64(time.Now().UnixNano()),
		now:     time.Now,
		rng:     mrand.NewChaCha8(seed),
	}
	copy(cd.macSend[:], sendKey)
	copy(cd.macRecv[:], recvKey)
	if !noCrypt {
		s, err := chacha20poly1305.NewX(sendKey)
		if err != nil {
			return nil, err
		}
		r, err := chacha20poly1305.NewX(recvKey)
		if err != nil {
			return nil, err
		}
		cd.send, cd.recv = s, r
	}
	return cd, nil
}

func (c *codec) useAES(sendKey, recvKey []byte) error {
	if c.noCrypt {
		return nil
	}
	var err error
	if c.send, c.maskSend, err = aesKeys(sendKey); err != nil {
		return err
	}
	c.recv, c.maskRecv, err = aesKeys(recvKey)
	return err
}

func aesKeys(k []byte) (cipher.AEAD, cipher.Block, error) {
	b, err := aes.NewCipher(k[:16])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, err
	}
	mask, err := aes.NewCipher(k[16:32])
	return gcm, mask, err
}

func (c *codec) overhead() int {
	if c.noCrypt {
		return AuthOverhead
	}
	return CryptOverhead
}

func (c *codec) room(n int) int {
	return n + c.overhead() + c.padding
}

func authMAC(key *[32]byte, body []byte) [authTagLen]byte {
	h := hmac.New(sha256.New, key[:])
	h.Write(body)
	var sum [32]byte
	h.Sum(sum[:0])
	var out [authTagLen]byte
	copy(out[:], sum[:authTagLen])
	return out
}

// seal writes the framed/encrypted packet into dst and returns the slice.
func (c *codec) seal(dst []byte, typ byte, pkt []byte, ts uint32) []byte {
	pad := 0
	if c.padding > 0 {
		var b [1]byte
		c.random(b[:])
		pad = int(b[0]) % (c.padding + 1)
	}
	seq := atomic.AddUint64(&c.seq, 1)
	if c.noCrypt {
		total := authTagLen + headerLen + len(pkt) + pad
		body := dst[authTagLen:total]
		body[0], body[1] = typ, byte(pad)
		binary.BigEndian.PutUint64(body[2:], seq)
		binary.BigEndian.PutUint32(body[10:], ts)
		copy(body[headerLen:], pkt)
		clear(body[headerLen+len(pkt):])
		tag := authMAC(&c.macSend, body)
		copy(dst[:authTagLen], tag[:])
		return dst[:total]
	}
	nonce := dst[:nonceLen]
	c.random(nonce)
	plain := dst[nonceLen : nonceLen+headerLen+len(pkt)+pad]
	plain[0], plain[1] = typ, byte(pad)
	binary.BigEndian.PutUint64(plain[2:], seq)
	binary.BigEndian.PutUint32(plain[10:], ts)
	copy(plain[headerLen:], pkt)
	clear(plain[headerLen+len(pkt):])
	if c.maskSend != nil {
		binary.BigEndian.PutUint64(nonce, seq)
		var gn [12]byte
		copy(gn[:], nonce[:12])
		c.maskSend.Encrypt(nonce[:16], nonce[:16])
		out := c.send.Seal(plain[:0], gn[:], plain, nil)
		return dst[:nonceLen+len(out)]
	}
	out := c.send.Seal(plain[:0], nonce, plain, nil)
	return dst[:nonceLen+len(out)]
}

// open authenticates (and decrypts when !noCrypt) a frame in place.
func (c *codec) open(d []byte) (byte, []byte, error) {
	if c.noCrypt {
		if len(d) < AuthOverhead {
			return 0, nil, errAuth
		}
		body := d[authTagLen:]
		want := authMAC(&c.macRecv, body)
		if subtle.ConstantTimeCompare(d[:authTagLen], want[:]) != 1 {
			return 0, nil, errAuth
		}
		typ, pad := body[0], int(body[1])
		seq := binary.BigEndian.Uint64(body[2:])
		ts := int64(binary.BigEndian.Uint32(body[10:]))
		if len(body) < headerLen+pad {
			return 0, nil, errAuth
		}
		if c.win.top == 0 {
			if diff := time.Duration(c.now().Unix()-ts) * time.Second; diff > maxSkew || diff < -maxSkew {
				return 0, nil, errAuth
			}
		}
		if !c.win.accept(seq) {
			return 0, nil, errAuth
		}
		return typ, body[headerLen : len(body)-pad], nil
	}
	if len(d) < CryptOverhead {
		return 0, nil, errAuth
	}
	nonce := d[:nonceLen]
	var block [16]byte
	if c.maskRecv != nil {
		c.maskRecv.Decrypt(block[:], d[:16])
		nonce = block[:12]
	}
	plain, err := c.recv.Open(d[nonceLen:nonceLen], nonce, d[nonceLen:], nil)
	if err != nil {
		return 0, nil, errAuth
	}
	typ, pad := plain[0], int(plain[1])
	seq := binary.BigEndian.Uint64(plain[2:])
	ts := int64(binary.BigEndian.Uint32(plain[10:]))
	if len(plain) < headerLen+pad {
		return 0, nil, errAuth
	}
	if c.win.top == 0 {
		if diff := time.Duration(c.now().Unix()-ts) * time.Second; diff > maxSkew || diff < -maxSkew {
			return 0, nil, errAuth
		}
	}
	if !c.win.accept(seq) {
		return 0, nil, errAuth
	}
	return typ, plain[headerLen : len(plain)-pad], nil
}

type window struct {
	top  uint64
	bits [windowSize / 64]uint64
}

func (w *window) accept(seq uint64) bool {
	switch {
	case w.top == 0 || seq > w.top:
		if w.top == 0 || seq-w.top >= windowSize {
			w.bits = [windowSize / 64]uint64{}
		} else {
			for s := w.top + 1; s < seq; s++ {
				w.clear(s)
			}
		}
		w.top = seq
		w.set(seq)
		return true
	case w.top-seq >= windowSize:
		return false
	default:
		if w.has(seq) {
			return false
		}
		w.set(seq)
		return true
	}
}

func (w *window) set(seq uint64)   { w.bits[(seq%windowSize)/64] |= 1 << (seq % 64) }
func (w *window) clear(seq uint64) { w.bits[(seq%windowSize)/64] &^= 1 << (seq % 64) }
func (w *window) has(seq uint64) bool {
	return w.bits[(seq%windowSize)/64]&(1<<(seq%64)) != 0
}
