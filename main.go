package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"dns_server/dns"
)

var (
	hostsFile *string
	port *int
)


func init() {
	hostsFile = flag.String("hosts", "hosts.txt", "path to hosts file")
	port = flag.Int("port", 9000, "the listened port number")
}

func main() {
	flag.Parse()
	
	if *port <= 1024 || *port > 65535 {
		fmt.Println("The port number is out of range (1024 - 65535)")
		os.Exit(-1)
	}
	
	file, err := os.OpenFile("dnsserver.log", os.O_CREATE | os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	
	log.SetOutput(file)
	
	application := dns.NewApplication(9000, "hosts")
	application.Run()
}