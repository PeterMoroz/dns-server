package main

import (
	"fmt"
	"net"
)


func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
		Port: 53,
	})

	if err != nil {
		fmt.Println("Could not create listen socket. ", err)
		return
	}
	
	defer conn.Close()
	
	for {
		var data[1024] byte
		n, addr, err := conn.ReadFromUDP(data[:])
		if err != nil {
			fmt.Println("Read data failed. ", err)
			continue
		}
		
		fmt.Printf("Request %v bytes from %v\n", n, addr)
		
		_, err = conn.WriteToUDP(data[:n], addr)
		if err != nil {
			fmt.Println("Write data failed. ", err)
			continue
		}
	}
}