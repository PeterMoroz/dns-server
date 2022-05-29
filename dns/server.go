package dns

import (
	"log"
	"net"
)

const (
	bufferSize = 1024
)

type Server struct {
	port int
	resolver *Resolver	
}

func (s Server) run() {
	log.Println("Server.run()")
	log.Println("Listen UDP port", s.port)
	
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: s.port})
	if err != nil {
		log.Fatalf("ListenUDP() failed. Error: %v\n", err)
	}
	defer conn.Close()
	
	buffer := make([]byte, bufferSize)
	
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err == nil {
			log.Printf("Received %d bytes from %v\n", n, addr)
			var q query
			q.decode(buffer)
			var r response
			s.resolver.reverseLookup(&q, &r)
			r.encode(buffer, &n)
			conn.WriteToUDP(buffer[:n], addr)
		} else {
			log.Printf("ReadFromUDP() failed. Address: %v Error: %v\n", addr, err)
			continue
		}
	}
}
