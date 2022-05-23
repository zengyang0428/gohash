package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

func main() {
	//1.对需要签名的文件进行hash运算
	// data := "from Steven to Danoel 10 BTC "
	// hashInsance := sha256.New()
	// hashInsance.Write([]byte(data))
	// hashed := hashInsance.Sum(nil)
	// //2.生成公钥和私钥
	// privatkey,publickeytes := NewKeyPair()
	// //3.生成签名的der编码格式
	// derSignString :=ECDSASign(hashed,privatkey)
	// fmt.Printf("签名信息为:%s\n",derSignString)

	// //验证签名
	// flag :=ECDSAVerify(publickeytes,hashed,derSignString)
	// fmt.Println("签名验证结果:",flag)

	NEwKeyPaor2()

}

//生成私钥和公钥，生成的私钥为结构体ecdsa.PrivateKey的指针
func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	//1.生成椭圆曲线对象
	//P256（）返回一条实现P-256的曲线
	curve := elliptic.P256()

	//2.生成密钥对，返回私钥对象(ecdsa,Prinvatekey指针)
	privatekey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	//3.编码生成公钥字节数组，参数是椭圆曲线对象，x坐标，y坐标
	publicKeyBytes := elliptic.Marshal(curve, privatekey.PublicKey.X, privatekey.PublicKey.Y)
	fmt.Printf("公钥:%x\n", publicKeyBytes)
	return *privatekey, publicKeyBytes
}

//生成密钥时，返回私钥和公钥的字节数组
func NEwKeyPaor2()(PrivateKeyBytes, PublicKeyBytes []byte) {
	//1.生成椭圆曲线对象
	//P256（）返回一条实现P-256的曲线
	curve := elliptic.P256()

	//2.生成密钥对，返回私钥对象(ecdsa,Prinvatekey),通过私钥对象生成私钥字节数组
	privatekey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	PrivateKeyBytes = privatekey.D.Bytes()
	fmt.Printf("私钥:%x\n", PrivateKeyBytes)
	//3.编码生成公钥字节数组，参数是椭圆曲线对象，x坐标，y坐标
	PublicKeyBytes = elliptic.Marshal(curve, privatekey.PublicKey.X, privatekey.PublicKey.Y)
	fmt.Printf("公钥:%x\n", PublicKeyBytes)
	return

}

//ECDSA数字签名
func ECDSASign(hashed []byte, privatekey ecdsa.PrivateKey) string {
	//1.数字签名生成r，s的big.Int对象 参数是随机数，私钥，签名文件的哈希串
	r, s, err := ecdsa.Sign(rand.Reader, &privatekey, hashed)
	if err != nil {
		return ""
	}
	//2.将r，s转成r，s字符串
	strSigR := fmt.Sprintf("%x", r)
	strSigS := fmt.Sprintf("%x", s)
	if len(strSigR) == 63 {
		strSigR = "0" + strSigR
	}
	if len(strSigS) == 63 {
		strSigS = "0" + strSigS
	}
	fmt.Printf("r的16进制为：%s,长度为:%d\n", strSigR, len(strSigR))
	fmt.Printf("S的16进制为：%s,长度为:%d\n", strSigS, len(strSigS))
	//3.r和s字符串，形成数字签名的der格式
	derString := MakeDERSignstring(strSigR, strSigS)
	return derString
}

//生成数字签名的DER编码格式
func MakeDERSignstring(strR, strS string) string {
	//1.获取R和S的长度
	lenSigR := len(strR) / 2
	lenSigS := len(strS) / 2
	//2.计算DER序列的总长度
	lem := lenSigR + lenSigS + 4
	//3.将10进制长度转16机制字符串
	strlenSigR := fmt.Sprintf("%x", int64(lenSigR))
	strlenSigS := fmt.Sprintf("%x", int64(lenSigS))
	strlen := fmt.Sprintf("%x", int64(lem))
	//4.拼接DER编码格式
	derString := "30" + strlen
	derString += "02" + strlenSigR + strR
	derString += "02" + strlenSigS + strS
	derString += "01"
	return derString

}

//EDCSA验证签名(比特币系统中公钥具有0x04前缀)
func ECDSAVerify(publicKeyBytes, hashed []byte, ERSignstring string) bool {
	//公钥长度
	keylen := len(publicKeyBytes)
	if keylen != 65 {
		return false
	}
	//1.生成椭圆曲线对象
	curve := elliptic.P256()
	//2.根据公钥字节数字，获取公钥中的x及y
	//公钥字节中前一半为x坐标，后一半为y轴坐标，再将字节数组转成big.Int类型
	publicKeyBytes = publicKeyBytes[1:]
	//x := big.NewInt(0).SetBytes(publicKeyBytes[:32])
	x := new(big.Int).SetBytes(publicKeyBytes[:32])
	y := new(big.Int).SetBytes(publicKeyBytes[32:])
	//3.生成公钥对象
	publicKey := ecdsa.PublicKey{curve, x, y}
	//4.对der格式的签名进行解析，获取r,s字节数据后转成big.Int类型
	rBytes, sBytes := ParseOERSignString(ERSignstring)
	//转换成big.Int类型
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	//5.验证签名，参数是公钥对象，签名文件的哈希串，数字签名的r和s对象
	return ecdsa.Verify(&publicKey, hashed, r, s)

}

func ECDSAVerify2(publicKeyBytes, hashed []byte, ERSignstring string) bool {
	//公钥长度
	keylen := len(publicKeyBytes)
	if keylen != 65 {
		return false
	}
	//1.生成椭圆曲线对象
	curve := elliptic.P256()
	//2.根据公钥字节数字，获取公钥中的x及y
	//公钥字节中前一半为x坐标，后一半为y轴坐标，再将字节数组转成big.Int类型
	publicKeyBytes = publicKeyBytes[1:]
	//x := big.NewInt(0).SetBytes(publicKeyBytes[:32])
	x := new(big.Int).SetBytes(publicKeyBytes[:32])
	y := new(big.Int).SetBytes(publicKeyBytes[32:])
	//3.生成公钥对象
	publicKey := ecdsa.PublicKey{curve, x, y}
	//4.对der格式的签名进行解析，获取r,s字节数据后转成big.Int类型
	rBytes, sBytes := ParseOERSignString(ERSignstring)
	//转换成big.Int类型
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	//5.验证签名，参数是公钥对象，签名文件的哈希串，数字签名的r和s对象
	flag := ecdsa.Verify(&publicKey, hashed, r, s)
	return flag
}

func ParseOERSignString(ERSstring string) (rBytes, sBytes []byte) {
	derBytes, _ := hex.DecodeString(ERSstring)
	rBytes = derBytes[4:36]
	sBytes = derBytes[len(derBytes)-33 : len(derBytes)-1]
	return
}
