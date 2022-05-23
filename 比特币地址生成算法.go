package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	
	//"golang.org/x/crypto/ripemd160"
)

var base58characterset = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func main() {
	pubkeystring := "0440e7da9eb24ff5b95ac2f74347ba6d9c632b9e8cfcdb14aacbc60bfb64a2deb2dc876498a90607c93c796eb676b36d8c593864e5a890704dd7acf156adb7f5d8"
	arr, _ := hex.DecodeString(pubkeystring)
	addr, _ := Generatebitcoinaddress(arr, 0)
	fmt.Println("base58编码:", addr)

	//验证比特币地址是否合法
	flag := base58chack(addr)

	fmt.Println("base58check", flag)

}

/*
根据公钥生成比特币地址
参数:公钥 网络类型
网络id号 *比特币主网ID号: 0x00 testnet测试网络Id号 0x6f
返回值: 比特币地址字符串，error
*/

func Generatebitcoinaddress(Publickey []byte, mettype int) (string, error) {
	fmt.Printf("公钥：%x\n", Publickey)
	//1.判断公钥有效性
	//通过比特币公钥的长度来判断其合法性
	if len(Publickey) != 65 && len(Publickey) != 33 {
		err := errors.New("公钥输入错误")
		return "", err
	}
	//2.计算公钥sha256
	sha256Bytes := HASH3(Publickey, crypto.SHA256)
	fmt.Printf("sha256:%x\n", sha256Bytes)
	//3.RipeMP160
	ripemp160Bytes := HASH3(sha256Bytes, crypto.RIPEMD160)
	fmt.Printf("ripemd160:%x\n", ripemp160Bytes)
	//4.增加网络Id号 比特币主网ID号0x00 testnet测试id号0x6f 私链网络id号 0x34
	var prefixByte []byte
	switch mettype {
	case 0:
		IntTbBytes(0x00, 1)
	case 1:
		IntTbBytes(0x6f, 1)
	case 2:
		IntTbBytes(0x34, 1)
	}
	//prefixBytes := append(prefixByte,ripemp160Bytes...)
	prefixBytes := append(prefixByte, ripemp160Bytes...)
	fmt.Printf("加前缀后:%x\n", prefixBytes)
	//5.计算再次hash
	sHA256DoubleBytes := SHA256DoubleBytes(prefixBytes)
	fmt.Printf("sha256两次之后:%x\n", sHA256DoubleBytes)
	//6.获取校验码
	checkcodeBytes := sHA256DoubleBytes[:4]
	fmt.Printf("校验码:%x\n", checkcodeBytes)
	//7.形成16进制比特币地址
	addersBytes := append(prefixBytes, checkcodeBytes...)
	//8.对地址进行Bast58编码
	_, base58String := Base58Encode(addersBytes)
	return base58String, nil
}

//验证比特币地址是否合法，其实就是base58check的过程
func base58chack(base58String string) bool {
	//1.base58解码，获取16进制的比特币地址
	base58Bytes, _ := BASe58Decode([]byte(base58String))
	//2.从地址中截取最后四个字节，这四个字节计算校验码
	checkcodeBytes := base58Bytes[len(base58Bytes)-4:]
	//3.去处校验码的比特币地址
	addrPrefixBytes := base58Bytes[:len(base58Bytes)-4]
	//4.将去除校验码后的双hash256，获取前四个字节，这也是校验码
	hashedBytes := SHA256DoubleBytes(addrPrefixBytes)
	codeBytes := hashedBytes[:4]
	//5.判断两种方式获取的校验码是否相同，相同制说明地址有效，否则地址无效
	if string(checkcodeBytes) == string(codeBytes) {
		return true
	}
	return false
}

//整型数据转成字节
//count表示字节长度
func IntTbBytes(n int, count byte) ([]byte, error) {
	switch count {
	case 1:
		tmp := int8(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes(), nil
	case 2:
		tmp := int16(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes(), nil
	case 3, 4:
		tmp := int32(n)
		bytesBuffer := bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes(), nil
	}
	return nil, fmt.Errorf("五")

}
func HASH3(data []byte, myhash crypto.Hash) []byte {
	var hashInstance hash.Hash
	hashInstance = myhash.New()
	hashInstance.Write(data)
	bytes := hashInstance.Sum(nil)
	return bytes

}
func SHA256DoubleBytes(data []byte) []byte {
	hashInstance := sha256.New()
	hashInstance.Write(data)
	bytes := hashInstance.Sum(nil)
	hashInstance.Reset()
	hashInstance.Write(bytes)
	bytes = hashInstance.Sum(nil)
	return bytes

}

//Int表示一个带符号的多精度整型，Int的零表示值0
//NewInt分配并返回一个新的Int
//SetBytes将参数解析为一个大端排序的无符号整型，将z设置为该值，并返回z
func Base58Encode(input []byte) ([]byte, string) {
	x := big.NewInt(0).SetBytes(input)
	//fmt.Println("x=",x)

	mod := &big.Int{}
	var retult []byte
	//被除数+除数=商....余数
	//fmt.Println("开始*****")
	for x.Cmp(big.NewInt(0)) != 0 {
		x.DivMod(x, big.NewInt(58), mod)
		//fmt.Println("mod=",mod)
		//fmt.Println("x=",x)
		retult = append(retult, base58characterset[mod.Int64()])
		//fmt.Println("result=",fmt.Sprintf("%s",retult))
		//fmt.Println("****一次循环结束*****")
	}
	//fmt.Println("整个循环结束*****")
	if input[0] == 0x00 {
		retult = append(retult, base58characterset[0])
	}
	ReverseBytes(retult)

	return retult, fmt.Sprintf("%s", retult)

}
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
		// fmt.Println(i,j)
		// if i==3{
		// 	break
		// }

	}
}

func BASe58Decode(input []byte) ([]byte, string) {
	result := big.NewInt(0)

	for _, b := range input {
		charIndex := bytes.IndexByte(base58characterset, b)
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(charIndex)))
	}
	decoded := result.Bytes()
	if input[0] == base58characterset[0] {
		decoded = append([]byte{0x00}, decoded...)
	}
	return decoded, string(decoded)
}
