package main

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	//"golang.org/x/crypto/ripemd160"
	//"golang.org/x/crypto/md4"
)

func MD5(text string, hashType string, isHex bool) string {
	var hashInstance hash.Hash
	switch hashType {
	case "md4":
		//hashInstance =
	case "md5":
		hashInstance = md5.New()
	case "sha1":
		hashInstance = sha1.New()

	case "ripemd160":
		//hashInstance = ripemd160.New()

	case "sha256":
		hashInstance = sha256.New()

	case "sha512":
		hashInstance = sha256.New()
	}
	if isHex {
		arr, _ := hex.DecodeString(text)
		hashInstance.Write(arr)
	} else {
		hashInstance.Write([]byte(text))
	}

	bytes := hashInstance.Sum(nil)
	return fmt.Sprintf("%x", bytes)
}
func SHA256double(text string, inHex bool) []byte {
	hashInstance := sha256.New()
	if inHex {
		arr, _ := hex.DecodeString(text)
		hashInstance.Write(arr)
	} else {
		hashInstance.Write([]byte(text))
	}
	bytes := hashInstance.Sum(nil)
	hashInstance.Reset()
	hashInstance.Write(bytes)
	bytes = hashInstance.Sum(nil)
	return bytes
}
func SHA256doublestring(text string, inHex bool) string {
	bytes := SHA256double(text, inHex)
	return fmt.Sprintf("%x", bytes)

}
func HASH2(text string,myhash crypto.Hash,isHex bool) string{
	var hashInstance hash.Hash
	hashInstance = myhash.New()
	if isHex{
		arr,_ :=hex.DecodeString(text)
		hashInstance.Write(arr)
	}else {
		hashInstance.Write([]byte(text))
	}
	bytes:= hashInstance.Sum(nil)
	return fmt.Sprintf("%x",bytes)
}
func main() {
	res := HASH2("123456", crypto.MD5, true)
	//res1 := SHA256doublestring("123456", false)
	fmt.Println(res)
	//fmt.Println(res1)
}
