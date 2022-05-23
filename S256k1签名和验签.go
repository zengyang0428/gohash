package main

import "fmt"

func init() {
	PublicKeyBytes, privateKeyBytes := secp256.GenerateKeyPair()
	fmt.Printf("私钥为:%x\n", privateKeyBytes)
	fmt.Printf("公钥为:%x\n", PublicKeyBytes)
}
func main() {

}
