package main

import (
	"crypto"
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
	str := "from Stven to Daniel 1BTC"
	bsse63Sig,_ :=RSASign([]byte(str),"./private.pem")
	fmt.Println("签名后的信息",bsse63Sig)
	
	err := RSAVerify([]byte(str),bsse63Sig,"./public.pem")
	if err ==nil{
		fmt.Println("验证签名ok")
	}else{
		fmt.Println("签名验证失败")
	}


}
func RSASign(data []byte,filename string) (string,error) {
	//1.选择hash算法，对需要签名的数据进行hash运算
	myhash := crypto.SHA256
	hashInstance := myhash.New()
	hashInstance.Write(data)
	hashed := hashInstance.Sum(nil)
	//2.读取私钥文件，解析出私钥对象
	privar,err :=Readprivatekey(filename)
	if err !=nil{
		return "",err
	}
	bytes,err:=rsa.SignPKCS1v15(rand.Reader,privar,myhash,hashed)
	//3.RSA数字签名(参数是随机数，私钥对象，哈希类型，签名文件的哈希串)，生成base64编码的签名字符串
	return base64.StdEncoding.EncodeToString(bytes),nil

}
//公钥验证数据签名是否正确
func RSAVerify(data []byte,base64Sig,filenaem string) error{
	//1.对base64编码的签名内容进行解码，返回签名字节
	bytes,err := base64.StdEncoding.DecodeString(base64Sig)
	if err !=nil{
		return err
	}
	//2.选择hash算法，对需要签名的数据进行hash运算
	myhash:= crypto.SHA256
	hashInstnce := myhash.New()
	hashInstnce.Write(data)
	hashed := hashInstnce.Sum(nil)
	//3.读取公钥文件。解析公钥对象
	publikey,err :=Readpublickey(filenaem)
	if err !=nil{
		return err
	}
	//4.RSA验证数字签名(参数是公钥对象，哈希类型，签名文件的哈希串，签名后的字节)
	return rsa.VerifyPKCS1v15(publikey,myhash,hashed,bytes)


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