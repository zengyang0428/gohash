package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
)

func main() {
	if err := GenerateRSAKey(); err != nil {
		log.Fatal("密钥生成失败")
	}
	log.Println("密钥生成成功")
}

func GenerateRSAKey() error {
	//1.RSA生成私钥文件的核心步骤
	//生成RSA密钥对
	var bits int

	flag.IntVar(&bits, "key flag", 1024, "密钥长度，默认为1024位")
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2.将私钥对象转换为DER编码形式
	derprivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	//3.创建私钥pem文件
	file, err := os.Create("./private.pem")
	if err != nil {
		return err
	}
	//4.对私钥信息进行编码，写入到私钥文件中
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derprivateKey,
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	//2.RSA生成公钥文件的核心步骤
	//生成公钥对象
	PublicKey := &privateKey.PublicKey
	//2.将公钥对象序列化为DER编码格式
	pub, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		return err
	}
	//创建公钥pem文件
	file, err = os.Create("./public.pem")
	if err != nil {
		return err
	}
	//4.对公钥信息进行编码，写入到公钥文件中
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pub,
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
