package dns

import (
	"fmt"
	"os"
	"testing"
)

const (
	numOfHostEntries = 10
	hostsFilename = "hosts.txt"
)

func createHostsFile() {
	file, err := os.Create(hostsFilename)
	if err != nil {
		fmt.Println("Could not create 'hosts.txt'")
		os.Exit(-1)
	}
	
	defer file.Close()
	
	for i := 1; i <= numOfHostEntries; i++ {
		file.WriteString(fmt.Sprintf("127.0.0.%d host%d\n", i, i))
	}
}

func TestLookUp(t *testing.T) {
	createHostsFile()
	
	resolver := Resolver{}
	resolver.init(hostsFilename)
	
	for i := 1; i <= numOfHostEntries; i++  {
		ipAddr := fmt.Sprintf("127.0.0.%d", i)		
		addr := resolver.getAddress(fmt.Sprintf("host%d", i))
		if addr != ipAddr {
			t.Error("Expected ", ipAddr, "\tgot ", addr)
		}
	}
	
	os.Remove(hostsFilename)
}

func TestReverseLookUp(t *testing.T) {
	createHostsFile()
	
	resolver := Resolver{}
	resolver.init(hostsFilename)
	
	for i := 1; i <= numOfHostEntries; i++  {
		nameExpected := fmt.Sprintf("host%d", i)
		name := resolver.getDomainName(fmt.Sprintf("127.0.0.%d", i))
		if nameExpected != name {
			t.Error("Expected ", nameExpected, "\tgot ", name)
		}
	}
	
	os.Remove(hostsFilename)
}
