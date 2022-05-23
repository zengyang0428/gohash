package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
)

func main() {
	//DES密钥
	//key := "12345678" //占8字节
	//3DES密钥
	//key := "qwertyuiopasdfghjklzxcvb" //占24字节
	//AES的密钥 key长度 16，24，32 bytes 对应AES-128，AES-192，AES-256
	key := "1234567890qwerty"

	keyBytes := []byte(key)
	str := "yang"
	ciphrArr, err := SCEncrypt([]byte(str), keyBytes, "aes")
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后字节数组:%v\n", ciphrArr)
	fmt.Printf("加密后16数组:%x\n", ciphrArr)

	originaBytes, err := SCDecrypt(ciphrArr, keyBytes, "aes")
	if err != nil {
		panic(err)
	}
	fmt.Println("解密后:", string(originaBytes))

	fmt.Println("----------------------")
	str = "Steven陪你学区块链"
	fmt.Println("原始字符串", str)
	cipherText, err := SCEncryptstring(str, key, "aes")
	if err != nil {
		panic(err)
	}
	fmt.Println("加密后", cipherText)

	originaText, err := SCDncryptstring(cipherText, key, "aes")
	if err != nil {
		panic(err)
	}
	fmt.Println("解密后", originaText)

}

//对称加密算法
func SCEncrypt(originaBytes, key []byte, scType string) ([]byte, error) {
	//1.实例化密码器block (参数为密钥)
	var err error
	var block cipher.Block
	switch scType {
	case "des":
		block, err = des.NewCipher(key)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
	case "aes":
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	fmt.Println("------", blockSize) //8还是16
	//2.对明文填充字节(参数为原始字节切片和密码对象的区块个数)
	paddingbytes := PKCSSPadding(originaBytes, blockSize)
	fmt.Println("填充后的字节切片", paddingbytes)
	//3.实例化加密模式(参数为密码器和密钥)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	fmt.Println("加密模式", blockMode)
	//4.对填充字节后的明文进行加密(参数为加密切片和填充字节切片)
	cipherBytes := make([]byte, len(paddingbytes))
	blockMode.CryptBlocks(cipherBytes, paddingbytes)
	return cipherBytes, nil
}

//解密字节切片，返回字节切片
func SCDecrypt(cipherBytes, key []byte, scType string) ([]byte, error) {
	//1.实例化密码器block (参数为密钥)
	//1.实例化密码器block (参数为密钥)
	var err error
	var block cipher.Block
	switch scType {
	case "des":
		block, err = des.NewCipher(key)
	case "3des":
		block, err = des.NewTripleDESCipher(key)
	case "aes":
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	//2.实例化解密模式(参数为密码器和密钥)
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//3.对密文进行解密(参数为填充字节切片和加密字节切片)
	paddingBytes := make([]byte, len(cipherBytes))
	blockMode.CryptBlocks(paddingBytes, cipherBytes)
	//4.去除填充的字节(参数为填充切片)
	originaBytes := PKC55UnPadding(paddingBytes)
	return originaBytes, nil
}
func SCEncryptstring(originaText, key, scType string) (string, error) {
	cipherBytes, err := SCEncrypt([]byte(originaText), []byte(key), scType)
	if err != nil {
		return "", err
	}
	base64str := base64.StdEncoding.EncodeToString(cipherBytes)
	return base64str, nil

}

func SCDncryptstring(cipherText, key, scType string) (string, error) {
	cipherBytes, _ := base64.StdEncoding.DecodeString(cipherText)
	cipherBytes, err := SCDecrypt(cipherBytes, []byte(key), scType)
	if err != nil {
		return "", err
	}
	return string(cipherBytes), nil

}

//填充字节的函数
func PKCSSPadding(data []byte, bolckSize int) []byte {
	padding := bolckSize - len(data)%bolckSize
	fmt.Println("要填充的字节", padding)
	//初始化一个元素为padding的切片
	slicel := []byte{byte(padding)}
	slice2 := bytes.Repeat(slicel, padding)
	return append(data, slice2...)

}
func ZerosPadding(data []byte, bolckSize int) []byte {
	padding := bolckSize - len(data)%bolckSize
	fmt.Println("要填充的字节", padding)
	//初始化一个元素为padding的切片
	slicel := []byte{0}
	slice2 := bytes.Repeat(slicel, padding)
	return append(data, slice2...)
}

//去除填充字节的函数
func PKC55UnPadding(data []byte) []byte {
	unpadding := data[len(data)-1]
	result := data[:len(data)-int(unpadding)]
	return result

}
func ZerosUnPadding(data []byte) []byte {
	return bytes.TrimRightFunc(data, func(r rune) bool {
		return r == 0
	})
}
