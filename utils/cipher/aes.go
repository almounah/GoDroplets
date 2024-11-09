package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("invalid blocksize")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("invalid PKCS7 data (empty or not padded)")
	}
	if len(b)%blocksize != 0 {
		return nil, errors.New("invalid PKCS7 data (empty or not padded)")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errors.New("invalid PKCS7 data (empty or not padded)")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
		return nil, errors.New("invalid PKCS7 data (empty or not padded)")
		}
	}
	return b[:len(b)-n], nil
}


func AesDecrypt(pkey *[]byte, pcipherText *[]byte) *[]byte {

    // Add AES env
	blockCipherer, err := aes.NewCipher(*pkey)
	if err != nil {
        fmt.Println("Error Creating Block Cipher")
		fmt.Println(err)
	}

    // Deref ciphered text
    toDecipher := *pcipherText

    // Retreive iv
	iv := toDecipher[:aes.BlockSize]
    
	cleartext := make([]byte, len(toDecipher) - aes.BlockSize)

    // Deciphering
	effectiveCipherer := cipher.NewCBCDecrypter(blockCipherer, iv)
    effectiveCipherer.CryptBlocks(cleartext, toDecipher[aes.BlockSize:])

    cleartextUnpadded,_ := pkcs7Unpad(cleartext, aes.BlockSize)

    return &cleartextUnpadded
}
