package dns

import (
	"fmt"
	"encoding/binary"
)

const (
	qrMask = 0x8000
	opcodeMask = 0x7800
	aaMask = 0x0400
	tcMask = 0x0200
	rdMask = 0x0100
	raMask = 0x8000
	rcodeMask = 0x000F
)

const (
	rcodeSuccess = 0
	rcodeFormatError = 1
	rcodeServerFailure = 2
	rcodeNameError = 3
	rcodeNotImplemented = 4
	rcodeRefused = 5
)

type header struct {
	id uint16
	qr bool
	opcode uint16
	aa bool
	tc bool
	rd bool
	ra bool
	rcode uint16
	
	qdCount uint16
	anCount uint16
	nsCount uint16
	arCount uint16
}

func (h *header) decode(buf []byte) {
	h.id = binary.BigEndian.Uint16(buf)
	var flags uint16 = 0
	flags = binary.BigEndian.Uint16(buf[2:])
	
	h.qr = (flags & qrMask) != 0
	h.opcode = flags & opcodeMask
	h.aa = (flags & aaMask) != 0
	h.tc = (flags & tcMask) != 0
	h.rd = (flags & rdMask) != 0
	h.ra = (flags & raMask) != 0
	
	h.qdCount = binary.BigEndian.Uint16(buf[4:])
	h.anCount = binary.BigEndian.Uint16(buf[6:])
	h.nsCount = binary.BigEndian.Uint16(buf[8:])
	h.arCount = binary.BigEndian.Uint16(buf[10:])
}

func (h *header) encode(buf []byte) {
	binary.BigEndian.PutUint16(buf[0:2], h.id)
	
	var flags uint16 = 0
	if h.qr {
		flags |= (0x01 << 15)
	}
	
	flags |= ((h.opcode & 0x000F) << 14)
	// ...
	flags |= ((h.rcode & 0x000F) << 0)
	
	binary.BigEndian.PutUint16(buf[2:4], flags)
	
	binary.BigEndian.PutUint16(buf[4:6], h.qdCount)
	binary.BigEndian.PutUint16(buf[6:8], h.anCount)
	binary.BigEndian.PutUint16(buf[8:10], h.nsCount)
	binary.BigEndian.PutUint16(buf[10:12], h.arCount)
}

func (h *header) toString() string {
	return fmt.Sprintf("{ id: %d  qdCount: %d  anCount: %d  nsCound: %d  arCount:  %d }",
						h.id, h.qdCount, h.anCount, h.nsCount, h.arCount)
}