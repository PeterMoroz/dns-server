package dns

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

type record struct {
	ipAddress string
	domainName string
}

type Resolver struct {
	records [] record
}

func (r *Resolver) init(pathToHosts string) {
	log.Println("Resolver.init() - pathToHosts:", pathToHosts)
	
	file, err := os.Open(pathToHosts)
	if err != nil {
		log.Fatalf("Could not open file '%s'. Error: %s", pathToHosts, err)
	}
	
	defer file.Close()
	
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	
	for fileScanner.Scan() {
		r.store(fileScanner.Text())
	}

	// r.printRecords()
}

func (resolver *Resolver) reverseLookup(q *query, r *response) {
	log.Println("Resolver.reverseLookup()")
	qname := q.qname
	idx := strings.Index(qname, ".in-addr.arpa")
	if idx > 0 {
		addr := strings.Split(qname[0:idx], ".")
		// reverse address's components in place
		halfLen := len(addr) / 2
		for i := 0; i < halfLen; i++ {
			j := len(addr) - i - 1
			addr[i], addr[j] = addr[j], addr[i]
		}
		name := resolver.getDomainName(strings.Join(addr, "."))
	
		r.header.id = q.header.id
		r.header.qr = true
		
		r.header.qdCount = 1
		r.header.anCount = 1
		
		r.rdata = name
		
		if len(name) == 0 {
			r.header.rcode = rcodeNameError
			r.rdlength = 1
		} else {
			r.header.rcode = rcodeSuccess
			r.rdlength = uint16(len(name) + 2)
		}
	}
}

func (r *Resolver) store(line string) {
	idx := strings.Index(strings.TrimSpace(line), " ")
	if idx == -1 {
		log.Println("wrong line ", line)
		return
	}
	
	ipAddress := line[0:idx]
	domainName := line[idx+1:]	
	
	r.records = append(r.records, record{strings.TrimSpace(ipAddress), strings.TrimSpace(domainName)})
}

func (r Resolver) printRecords() {
	fmt.Println("**************** hosts records ****************")
	for _, rec := range r.records {
		fmt.Printf(" - %15s :: %s\n", rec.ipAddress, rec.domainName)
	}
}

func (r Resolver) getAddress(domainName string) string {
	log.Println("Resolver.getAddress() - domainName:", domainName)
	for _, rec := range r.records {
		if rec.domainName == domainName {
			return rec.ipAddress
		}
	}
	return ""
}

func (r Resolver) getDomainName(ipAddress string) string {
	log.Println("Resolver.getDomainName() - ipAddress:", ipAddress)	
	for _, rec := range r.records {
		if rec.ipAddress == ipAddress {
			return rec.domainName
		}
	}
	return ""
}
