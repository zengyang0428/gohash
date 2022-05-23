package main

import (
	"encoding/base64"
	"fmt"
)

func main()  {
	str := "Mac"
	res := Base64EncodeString(str)
	fmt.Println(res)
	turn,_:=Base64DecodeString(res)
	fmt.Println(turn)
}
func Base64EncodeString(str string) string  {
	return base64.StdEncoding.Strict().EncodeToString([]byte(str))


}

func Base64DecodeString(str string) (string,[]byte) {
	result,_ := base64.StdEncoding.DecodeString(str)
	return string(result),result





}