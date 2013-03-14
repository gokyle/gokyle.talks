package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
)

const KeySize = 16

var (
	ErrRandomFailure = fmt.Errorf("failed to read enough random data")
	ErrPadding       = fmt.Errorf("invalid padding")
)

// Random returns a byte slice containing size random bytes.
func Random(size int) (b []byte, err error) {
	b = make([]byte, size)
	n, err := rand.Read(b)
	if err != nil {
		return
	} else if size != n {
		err = ErrRandomFailure
	}
	return
}

// GenerateKey returns a key suitable for AES-128 cryptography.
func GenerateKey() (key []byte, err error) {
	return Random(KeySize)
}

// GenerateIV returns an initialisation vector suitable for
// AES-CBC encryption.
func GenerateIV() (iv []byte, err error) {
	return Random(aes.BlockSize)
}

// Implement the standard padding scheme for block ciphers. This
// scheme uses 0x80 as the first non-NULL padding byte, and 0x00 to
// pad out the data to a multiple of the block length as required.
// If the message is a multiple of the block size, add a full block
// of padding. Note that the message is copied, and the original
// isn't touched.
func PadBuffer(m []byte) (p []byte, err error) {
	mLen := len(m)

	p = make([]byte, mLen)
	copy(p, m)

	if len(p) != mLen {
		return p, ErrPadding
	}

	padding := aes.BlockSize - mLen%aes.BlockSize

	p = append(p, 0x80)
	for i := 1; i < padding; i++ {
		p = append(p, 0x0)
	}
	return
}

// Encrypt encrypts a message, prepending the IV to the beginning.
func Encrypt(key []byte, msg []byte) (ct []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	iv, err := GenerateIV()
	if err != nil {
		return
	}

	var tmp_ct []byte
	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(tmp_ct, msg)
	ct = iv
	ct = append(ct, tmp_ct...)

	return
}

var ErrInvalidIV = fmt.Errorf("invalid IV")

// Decrypt takes an encrypted messages and decrypts it.
func Decrypt(key []byte, ct []byte) (msg []byte, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	// Make sure we don't touch the original slice.
	tmp_ct := make([]byte, len(ct))
	copy(tmp_ct, ct)
	iv := tmp_ct[:aes.BlockSize]
	if len(iv) != aes.BlockSize {
		return msg, ErrInvalidIV
	}
	tmp_ct = tmp_ct[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(msg, ct)
	return
}

func PadHelloWorld() {
	msg := []byte("Hello world")
	fmt.Printf("Original message: %+v\n", msg)
	padded, err := PadBuffer(msg)
	if err != nil {
		fmt.Println("[!] padding error:", err.Error())
		return
	}
	fmt.Printf("Padded message: %+v\n", padded)
}

func DemoEncryption() {
	msg := []byte("Hello, world")
	key, err := GenerateKey()
	if err != nil {
		fmt.Println("[!] couldn't generate key:", err.Error())
		return
	}

	ct, err := Encrypt(key, msg)
	if err != nil {
		fmt.Println("[!] encryption failure:", err.Error())
		return
	}

	fmt.Printf("ciphertext: %s\n", string(ct))
}

func main() {
	var SlideDemo = make(map[int]func(), 0)

	SlideDemo[11] = PadHelloWorld
	SlideDemo[17] = DemoEncryption

	slide := flag.Int("slide", 0, "slide number")
	flag.Parse()

	f, ok := SlideDemo[*slide]
	if !ok {
		fmt.Println("slides with demos:")
		for k, _ := range SlideDemo {
			fmt.Printf("%d, ", k)
		}
		fmt.Println("")
		return
	}

	f()

}


