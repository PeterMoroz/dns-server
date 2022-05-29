package dnsresolver

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"encoding/binary"
	"strings"
)

const headerLength = 12;
const packageLength = 512;


const rcodeNoError = 0x0;		// DNS Query completed successfully
const rcodeFormError = 0x1;		// DNS Query format error
const rcodeSerFail = 0x2;		// Server failed to complete the DNS request
const rcodeNxDomain = 0x3;		// Domain name does not exist
const rcodeNotImp = 0x4;		// Function not implemented
const rcodeRefused = 0x5;		// The server refused to answer for the query
const rcodeYxDomain = 0x6;		// Name that should not exist, does exist
const rcodeXrrSet = 0x7;		// RRset that should not exist, does exist
const rcodeNotAuth = 0x8;		// Server not authoritative for the zone
const rcodeNotZone = 0x9;		// Name not in zone


type dnsRecord struct {
	name string
	ttl uint32
	dnsClass uint16
	rrType uint16
	rdlength uint16
	rdata string
}

type soaRecord struct {
	dnsRecord
	serialNumber uint32
	timeToRefresh uint32
	timeToRetry uint32
	timeToExpire uint32
	minimumTTL uint32
}

var (
	dnsClasses = map[string] uint16 { "IN": 0x0001 }
	
	// The most common DNS records are described in detail in the RFC 1034 and RFC 1035
	rrTypes = map[string] uint16 { 
		"A": 1,			// address IPv4
		"NS": 2,		// nameserver
		"CNAME": 5,		// canonical name
		"SOA": 6,		// start of authority
		"PTR": 12,		// pointer
		"MX": 15,		// mail exchange
		"TXT": 16,		// text
		"AAAA": 28,		// address IPv6
		"SRV": 33,		// service
		"CAA": 257,		// certificate authority authorization
	}
	
	directives map[string] string
	records [] dnsRecord
	soaRec soaRecord
)


func init() {
	zonesPath := "./zones"
	dir, err := os.Open(zonesPath)
	if err != nil {
		// a simple trick to run test suite from package's directory but not the parent one
		dir, err = os.Open("../zones")
		if err != nil {
			fmt.Println("Could not find directory zones!")
			return
		}
		zonesPath = "../zones"
	}	
	defer dir.Close()
	
	files, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println("Could not read 'zones' directory content!")
		return
	}

	for _, f := range files {
		fmt.Println("file: ", f.Name())
		file, err := os.Open(filepath.Join(zonesPath, f.Name()))
		if err != nil {
			fmt.Println("Couldn't open file. ", err)
			continue
		}
		
		defer file.Close()
		

		// TO DO: process multiple files
		directives = make(map[string] string)			
		records = make([] dnsRecord, 0)	
		
		fileScanner := bufio.NewScanner(file)
		fileScanner.Split(bufio.ScanLines)

		var soaBuffer string	
		soaInProgress := false
		
		for fileScanner.Scan() {
			line := fileScanner.Text()
			if len(line) == 0 {
				continue
			}
			
			if strings.HasPrefix(line, "$") {
				fmt.Println("directive: ", line)
				var key, val string
				_, err := fmt.Sscanf(line, "$%s %s", &key, &val)
				if err != nil {
					fmt.Println("Error when processing directive ", line)
					continue
				}
				
				directives[key] = val
			} else {
				idx1 := strings.Index(line, "(")
				idx2 := strings.Index(line, ")")
				
				if (idx1 > 0 && idx2 > 0) {
					// TO DO: proces SOA as a single string
				} else if idx1 > 0 {
					soaBuffer = line
					soaInProgress = true
				} else if idx2 > 0 {
					soaBuffer += line
					soaInProgress = false
					fmt.Println("SOA ", soaBuffer)
					// TO DO: proces SOA as a single string
				} else {
					if soaInProgress {
						idx := strings.Index(line, ";")
						if idx > 0 {
							line = line[0:idx]	// skip comment
						}
						soaBuffer += line
					} else {
						fmt.Println("record: ", line)
						var name  string	// if contains free-standing @ this denotes current ORIGIN (see directives), if this field has 'www' or 'ftp', etc., this can denote a subdomain of the current ORIGIN
						var ttl uint32 = 0
						var dnsClass string
						var rrType string
						var rdlength uint16 = 0
						var rdata string
						n, err := fmt.Sscanf(line, "%s %d %s %s %d %s", &name, &ttl, &dnsClass, &rrType, &rdlength, &rdata)
						if err != nil {
							// fmt.Println("Sscanf failed. n = ",  n, " error: ", err)
							if n == 5 {
								n, err = fmt.Sscanf(line, "%s %d %s %s %s", &name, &ttl, &dnsClass, &rrType, &rdata)
								if err != nil {
									fmt.Println("Sscanf failed. expected 5 fields, actual:",  n, " error: ", err)
									continue
								}
							} else if n == 4 {
								n, err = fmt.Sscanf(line, "%s %s %s %s", &name, &dnsClass, &rrType, &rdata)
								if err != nil {
									fmt.Println("Sscanf failed. expected 4 fields, actual ",  n, " error: ", err)
									continue
								}				
							}
						}
						
						if rrType == "A" {
							rdlength = 4
						} else if rrType == "AAAA" {
							rdlength = 16
						}
						
						record := dnsRecord{name, ttl, dnsClasses[dnsClass], rrTypes[rrType], rdlength, rdata}
						records = append(records, record)
					}
				}
			}	
		}
	}
}

type resolver struct {
	requestData [] byte
	formatError bool
}

func New(requestData [] byte) resolver {
	r := new(resolver)
	r.requestData = requestData
	r.formatError = false
	return *r
}

func (r resolver) Response() [] byte {

	// parse DNS Question
	labels := make([]string, 0)	
	var i byte = 12
	n := r.requestData[i]
	for n != 0 {
		i += 1
		labels = append(labels, string(r.requestData[i:i+n]))
		i += n
		n = r.requestData[i]
	}
	
	i += 1	
	qtype := binary.BigEndian.Uint16(r.requestData[i:i+2])

	answers := r.getAnswers(labels, qtype)
	
	response := make([]byte, headerLength, packageLength)	// the initial length is equal to length of the header and the capacity is max length of DNS package
	header := r.makeHeader(uint16(len(answers)))
	copy(response, header[:])	
	
	response = append(response, r.makeQuestionSection(labels, qtype)...)
	response = append(response, r.makeAnswersSection(answers, qtype)...)
	return response
}

type dnsAnswer struct {
	ttl uint32
	rdlength uint16
	rdata [] byte
}

func (r resolver) getAnswers(labels []string, qtype uint16) [] dnsAnswer {
	name := strings.Join(labels, ".")
	name = name + "."	// ineficient
	
	encodeRdata := func(rdata string, qtype uint16) []byte {
		if qtype == 1 {	// support only Address IPv4 for now
			result := make([]byte, 4)
			n, err := fmt.Sscanf(rdata, "%d.%d.%d.%d", &result[0], &result[1], &result[2], &result[3])
			if n != 4 || err != nil {
				fmt.Println("Sscanf failed. expected 4 fields, actual ",  n, " error: ", err)
				return nil
			}
			return result
		}
		return nil
	}
	
	// fmt.Printf("r.getAnswers() - requested domain name '%s', query type %d\n", name, qtype)

	answers := make([] dnsAnswer, 0)
		
	for _, record := range records {
		if (record.name == name && record.rrType == qtype) {
			fmt.Printf("found record: %v\n", record)
			rdata := encodeRdata(record.rdata, qtype)
			if rdata != nil {
				answer := dnsAnswer{record.ttl, uint16(len(rdata)), rdata}
				answers = append(answers, answer)
			} else {
				fmt.Println("Could not encode rdata (record %v, qtype %d)\n", record, qtype)
				continue
			}
		}
	}
		
	return answers
}

func (r resolver) makeHeader(ancount uint16) [12] byte {
	var header[12] byte
	// copy ID from query
	header[0] = r.requestData[0]
	header[1] = r.requestData[1]
	
	// get opcode from request
	var flags uint16 = binary.BigEndian.Uint16(r.requestData[2:])
	var opcode uint16 = (flags >> 11) & 0x0F
	
	var rcode uint16 = rcodeNoError
	if r.formatError {
		rcode = rcodeFormError
	} else if ancount == 0 {
		rcode = rcodeNxDomain
	}

	flags = 0
	flags |= (0x01 << 15)	// 15th bit is query bit: 0/1 - query/reply
	flags |= (opcode << 14)	// the bits 14-11 is opcode value
	flags |= (0x01 << 10)	// 10th bit - authoritative answer
	flags |= (0x00 << 9)	// 9th bit - truncation flags
	flags |= (0x00 << 8)	// 8th bit - recursion desired
	flags |= (0x00 << 7)	// 7th bit - recursion enabled
	flags |= (0x00 << 6)	// the bits 6-4 are reserved for now and should be zero
	flags |= (rcode	<< 0)	// the bits 3-0 is response code

	// put flags
	binary.BigEndian.PutUint16(header[2:], flags)
	
	// put sections counters
	binary.BigEndian.PutUint16(header[4:], 0x0001)	// questions count
	binary.BigEndian.PutUint16(header[6:], ancount)	// answers count
	binary.BigEndian.PutUint16(header[8:], 0x0000)	// name servers count	
	binary.BigEndian.PutUint16(header[10:], 0x0000)	// additional records count
	
	return header
}

func (r resolver) makeQuestionSection(labels [] string, qtype uint16) [] byte {
	section := make([]byte, 0, 64)	// just arbitrary capacity
	if r.formatError {
		return section
	}
	
	for _, s := range labels {
		section = append(section, byte(len(s)))
		section = append(section, []byte(s)...)
	}
	section = append(section, 0x00)
	
	offset := len(section)
	section = append(section, []byte{0x00, 0x00, 0x00, 0x00}...)
	binary.BigEndian.PutUint16(section[offset:], qtype)		// type
	binary.BigEndian.PutUint16(section[offset+2:], 0x0001)	// class
	return section
}

func (r resolver) makeAnswersSection(answers [] dnsAnswer, qtype uint16) [] byte {
	section := make([]byte, 0, 64)	// just arbitrary capacity
	if r.formatError || len(records) == 0 {
		return section
	}
	
	section = append(section, []byte{0xC0, 0x0C, 0x00, 0x00, 0x00, 0x00}...)
	offset := 2
	binary.BigEndian.PutUint16(section[offset:], qtype)
	offset += 2
	binary.BigEndian.PutUint16(section[offset:], 0x0001)
	offset += 2
	
	for _, answer := range answers {
		section = append(section, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)	
		binary.BigEndian.PutUint32(section[offset:], answer.ttl)
		offset += 4
		binary.BigEndian.PutUint16(section[offset:], answer.rdlength)
		offset += 2
		section = append(section, answer.rdata...)
		offset += int(answer.rdlength)
	}
	
	return section
}
