package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
)
var base58characterset = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
func main()  {
	//testReverse()
	str := "一a"
	_,res := Base58Encode([]byte(str))
	fmt.Println(res)

	_,res = BASe58Decode([]byte(res))
	fmt.Println(res)

}
//Int表示一个带符号的多精度整型，Int的零表示值0
//NewInt分配并返回一个新的Int
//SetBytes将参数解析为一个大端排序的无符号整型，将z设置为该值，并返回z
func Base58Encode(input []byte)([]byte,string)  {
	x := big.NewInt(0).SetBytes(input)
	fmt.Println("x=",x)

	mod := &big.Int{}
	var retult []byte
	//被除数+除数=商....余数
	//fmt.Println("开始*****")
	for x.Cmp(big.NewInt(0)) != 0 {
		x.DivMod(x,big.NewInt(58),mod)
		//fmt.Println("mod=",mod)
		//fmt.Println("x=",x)
		retult = append(retult,base58characterset[mod.Int64()])
		//fmt.Println("result=",fmt.Sprintf("%s",retult))
		//fmt.Println("****一次循环结束*****")
	}
	//fmt.Println("整个循环结束*****")
	ReverseBytes(retult)


	return retult,fmt.Sprintf("%s",retult)

}
//BASe58Decode decodes Base58-encoded data
func BASe58Decode(input []byte)([]byte,string)  {
	result := big.NewInt(0)

	for _,b := range input {
		charIndex := bytes.IndexByte(base58characterset,b)
		result.Mul(result,big.NewInt(58))
		result.Add(result,big.NewInt(int64(charIndex)))
	}
	decoded := result.Bytes()
	if input[0] == base58characterset[0]{
		decoded = append([]byte{0x00},decoded...)
	}
	return decoded,string(decoded)
}
func testReverse()  {
	str := "12345678"
	//data := []byte(str)
	data,_ := hex.DecodeString(str)
	ReverseBytes(data)
	fmt.Println(fmt.Sprintf("%x",data))
}
func ReverseBytes(data []byte)  {
	for i,j :=0,len(data)-1; i < j ; i,j = i+1,j-1{
		data[i],data[j] = data[j],data[i]
		// fmt.Println(i,j)
		// if i==3{
		// 	break
		// }
	
	}
}