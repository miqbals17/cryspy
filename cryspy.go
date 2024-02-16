package cryspy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func EncryptECB(plaintext string, key string) []byte {
	var bPlaintext = []byte(plaintext)
	var bKey = []byte(key)
	var ciphertext []byte

	padded_bPlaintext := PKCS5Padding(bPlaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded_bPlaintext))

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	block.Encrypt(ciphertext, padded_bPlaintext)

	return ciphertext
}

func DecryptECB(ciphertext string, key string) []byte {
	var bCiphertext = []byte(ciphertext)
	var bKey = []byte(key)

	var plaintext []byte
	var trimmedPlaintext []byte

	plaintext = make([]byte, len(bCiphertext))

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	block.Decrypt(plaintext, bCiphertext)

	trimmedPlaintext = PKCS5Trimming(plaintext, aes.BlockSize)

	return trimmedPlaintext
}

func EncryptCBC(plaintext string, key string, iv string) []byte {
	var bPlaintext = []byte(plaintext)
	var bKey = []byte(key)
	var bIv = []byte(iv)
	var ciphertext []byte

	padded_bPlaintext := PKCS5Padding(bPlaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded_bPlaintext))

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	blockCBC := cipher.NewCBCEncrypter(block, bIv)

	blockCBC.CryptBlocks(ciphertext, padded_bPlaintext)

	return ciphertext
}

func DecryptCBC(ciphertext string, key string, iv string) []byte {
	var bCiphertext = []byte(ciphertext)
	var bKey = []byte(key)
	var bIv = []byte(iv)

	var plaintext []byte
	var trimmedPlaintext []byte

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	plaintext = make([]byte, len(bCiphertext))

	blockCBC := cipher.NewCBCDecrypter(block, bIv)
	blockCBC.CryptBlocks(plaintext, bCiphertext)

	trimmedPlaintext = PKCS5Trimming(plaintext, aes.BlockSize)

	return trimmedPlaintext
}

func PKCS5Padding(plaintext []byte, blocksize int) []byte {
	//Calculate padding for plaintext
	paddingSize := blocksize - len([]byte(plaintext))%blocksize
	paddingByte := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

	//Concatenate padding and plaintext
	paddedText := append([]byte(plaintext), paddingByte...)

	return paddedText
}

func PKCS5Trimming(plaintext []byte, blocksize int) []byte {
	//Calculate paddingsize
	paddingSize := plaintext[len(plaintext)-1]

	//Trim plaintext from padding
	trimmedText := plaintext[:len(plaintext)-int(paddingSize)]

	return trimmedText
}
