package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	
)

func main(){
	str := "Steven陪你学区块链-¥%#@！"
	fmt.Println("原始字符串",str)
	ciphrText, err := RSAEncryptString((str),"./public.pem")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("加密后",ciphrText)
	fmt.Println("------------")
	originaBytes,err := RSADecryptstring(ciphrText,"./private.pem")
	if err != nil {
		fmt.Println(err)
	}	
	fmt.Println("解密后字符串",originaBytes)
}
//RSA加密字节数组，返回字节数组
func RSAEncrypt(originaBytes []byte,filename string) ([]byte,error)  {
	//1.读取公钥文件，解析出公钥对象
	publickey,err := Readpublickey(filename)
	if err != nil{
		return nil,err
	}
	//2.RSA加密，参数是随机数，公钥对象，需要加密的字节
	//Reader是一个全局共享的密码安全地强大的伪随机生成器
	return rsa.EncryptPKCS1v15(rand.Reader,publickey,originaBytes)




}
//RSA解迷字节数组，返回字节数组
func RSADecrypt(cipherBytes []byte,filename string) ([]byte,error)  {
	//1.读取私钥文件，解析出私钥对象
	publickey,err := Readprivatekey(filename)
	if err != nil{
		return nil,err
	}
	//2.rsa解密，参数是随机，私钥对象，需要解密的字节
	return rsa.DecryptPKCS1v15(rand.Reader,publickey,cipherBytes)



}

//读取公钥文件，解析出公钥对象
func Readpublickey(filename string) (*rsa.PublicKey,error) {
	//1.读取公钥文件，获取公钥字节
	PublicKeyBytes,err :=ioutil.ReadFile(filename)
	if err != nil{
		return nil,err
	}
	//2.解码公钥字节，生成加密块对象
	block, _ := pem.Decode(PublicKeyBytes)
	if block == nil{
		return nil,errors.New("公钥信息错误")
	}
	//3.解析DER编码的公钥，生成公钥接口
	pub,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil{
		return nil,err
	}
	//4.公钥接口转型成公钥对象
	publicKey := pub.(*rsa.PublicKey)
	return publicKey,nil
}


//读取私钥文件，解析出私钥对象
func Readprivatekey(filename string)(*rsa.PrivateKey,error)  {
	//1.读取私钥文件，获取私钥字节
	privateKeyBytes,err := ioutil.ReadFile(filename)
	if err != nil{
		return nil,err
	}
	//2.对私钥文件进行解码，生成加密块对象
	block,_ := pem.Decode(privateKeyBytes)
	if block == nil{
		return nil,errors.New("私钥信息错误")
	}
	//3.解析DER编码的私钥，生成私钥对象
	der,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil{
		return nil,err
	}
	return der,nil
}
//RSA加密字符串，返回base64处理的字符串
func RSAEncryptString(originastring,filename string) (string,error)  {
	originasByste,err :=RSAEncrypt([]byte(originastring),filename)
	if err != nil{
		return "",err
	}
	return base64.StdEncoding.EncodeToString(originasByste),nil
}





//RSA解密经过base64处理的加密字符串，返回加密前的明文
func RSADecryptstring(ciphrstring,filename string) (string,error)  {
	ciphrBytes,_:=base64.StdEncoding.DecodeString(ciphrstring)
	or,err :=RSADecrypt(ciphrBytes,filename)
	if err != nil{
		return "",err
	}
	return string(or),nil
}


