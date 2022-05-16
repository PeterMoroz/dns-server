package dnsresolver

import (
	"fmt"
	"os"
	"io/ioutil"
	"encoding/json"
	"path/filepath"
	"encoding/binary"
	"strings"
	"strconv"
)

var (
	zones map[string]interface{}
	queryTypeName map[uint16]string
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


func init() {
	zones = make(map[string](interface{}))
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
		bs, err := ioutil.ReadFile(filepath.Join(zonesPath, f.Name()))
		if err != nil {
			fmt.Println("ReadFile failed. ", err)
			continue
		}
		
		var zone map[string]interface{}		// zone := make(map[string](interface{}))
		err = json.Unmarshal(bs, &zone)
		if err != nil {
			fmt.Printf("Unmarshal JSON failed (file %s). %s\n", f.Name(), err.Error())
			continue
		}
			
		origin := zone["$origin"].(string)
		zones[origin] = zone
	}
	
	queryTypeName = make(map[uint16]string)
	queryTypeName[0x0001] = "a"
	queryTypeName[0x0002] = "ns"
	queryTypeName[0x0005] = "cname"
	queryTypeName[0x000f] = "mx"
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
	records, qtype, domainNameSegments := r.getRecords()
	
	response := make([]byte, headerLength, packageLength)	// the initial length is equal to length of the header and the capacity is max length of DNS package
	header := r.makeHeader(uint16(len(records)))
	copy(response, header[:])	
	
	response = append(response, r.makeQuestionSection(domainNameSegments, qtype)...)
	response = append(response, r.makeAnswersSection(records, qtype)...)
	return response
}

type dnsRecord struct {
	ttl uint32
	rdlength uint16
	rdata [] byte
}

func (r resolver) getRecords() ([] dnsRecord, uint16, [] string) {
	domainNameSegments := make([]string, 0)
	
	data := r.requestData[12:]
	var i byte = 0
	n := data[i]
	for n != 0 {
		i += 1
		domainNameSegments = append(domainNameSegments, string(data[i:i+n]))
		i += n
		n = data[i]
	}
		
	i += 1	
	qtype := binary.BigEndian.Uint16(data[i:i+2])
	domainRecords := make([] dnsRecord, 0)
	
	qname, qnameOk := queryTypeName[qtype]
	if qnameOk == true {
		domainName := strings.Join(domainNameSegments, ".")
		zone, zoneOk := zones[domainName]
		if zoneOk == true {
			records, recordsOk := zone.(map[string] interface{})[qname]
			if recordsOk == true {
				fmt.Println("records: ", records)
				fmt.Printf("records type %T\n", records)
				for _, r := range records.([]interface{}) {					
					fmt.Printf("record type %T, record value %#v \n", r, r)
					for k, v := range r.(map[string] interface{}) {
						fmt.Printf("key: %s, value type: %T\n", k, v)
					}
					
					ttl := r.(map[string]interface{})["ttl"].(float64)
					data := r.(map[string]interface{})["value"].(string)
					
					record := dnsRecord{ttl: uint32(ttl), rdlength: 0 }
					
					switch qtype {
						case 0x0001:
							record.rdlength = 4
							record.rdata = make([]byte, 0, 4)
							
							octets := strings.Split(data, ".")
							if len(octets) == 4 {
								record.rdata = append(record.rdata, []byte{0x00, 0x00, 0x00, 0x00}...)
								for i, s := range octets {
									x, _ := strconv.ParseInt(s, 10, 16)	// use 16-bit length, because signed int is returned
									record.rdata[i] = byte(x)
								}
							}
														
						default:
							record.rdlength = 0
							record.rdata = make([]byte, 0)
					}
					
					domainRecords = append(domainRecords, record)
				}
			} else {
				fmt.Println("No entries for type ", qname)
			}
		} else {
			fmt.Println("No information about ", domainName)
		}
	}
	
	return domainRecords, qtype, domainNameSegments
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

func (r resolver) makeQuestionSection(domainNameSegments [] string, qtype uint16) [] byte {
	section := make([]byte, 0, 64)	// just arbitrary capacity
	if r.formatError {
		return section
	}
	
	for _, s := range domainNameSegments {
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

func (r resolver) makeAnswersSection(records [] dnsRecord, qtype uint16) [] byte {
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
	
	for _, record := range records {
		section = append(section, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)	
		binary.BigEndian.PutUint32(section[offset:], record.ttl)
		offset += 4
		binary.BigEndian.PutUint16(section[offset:], record.rdlength)
		offset += 2
		section = append(section, record.rdata...)
		offset += int(record.rdlength)
	}
	
	return section
}

func Resolve(hostname string) string {
	fmt.Printf("Resolving the hostname: %s\n", hostname)
	return "10.0.0.1"
}