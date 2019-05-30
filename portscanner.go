package main

import "os"
import "fmt"
import "net"
import "time"
import "encoding/binary"
import "strconv"
import "bytes"
import "math/rand"

type TCPHeader struct {
    SrcPort  uint16
    DstPort  uint16
    Seq      uint32
    Ack      uint32
    HdrSize  uint8
    Flags    uint8 // ignore NS flag
    Window   uint16
    Checksum uint16
    Urgent   uint16
    // no options
}

func (hdr TCPHeader) ToBytesAndCsum(src net.IP, dst net.IP) []byte {
    buf := make([]byte, 20)
    binary.BigEndian.PutUint16(buf, hdr.SrcPort)
    binary.BigEndian.PutUint16(buf[2:], hdr.DstPort)
    binary.BigEndian.PutUint32(buf[4:], hdr.Seq)
    binary.BigEndian.PutUint32(buf[8:], hdr.Ack)
    buf[12] = hdr.HdrSize << 4
    buf[13] = hdr.Flags
    binary.BigEndian.PutUint16(buf[14:], hdr.Window)
    binary.BigEndian.PutUint16(buf[16:], 0)
    binary.BigEndian.PutUint16(buf[18:], hdr.Urgent)

    pseudobuf := make([]byte, len(buf) + 12)
    copy(pseudobuf, src.To4())
    copy(pseudobuf[4:], dst.To4())
    pseudobuf[8] = 0
    pseudobuf[9] = 6
    pseudobuf[10] = byte(len(buf) >> 8)
    pseudobuf[11] = byte(len(buf) & 0x00ff)
    copy(pseudobuf[12:], buf)

    csum := checksum(pseudobuf, len(pseudobuf))
    binary.LittleEndian.PutUint16(buf[16:], csum) // don't know why

    return buf
}

func BytesToTCPHeader(b []byte) TCPHeader {
    var header TCPHeader
    r := bytes.NewReader(b)
    err := binary.Read(r, binary.BigEndian, &header)
    if err != nil {
        panic(err.Error())
    }
    return header
}

func IPToLong(ip string) uint32 {
    var long uint32
    binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
    return long
}

func checksum(buf []byte, size int) uint16 {
    var sum uint32 = 0;

	/* Accumulate checksum */
    for i := int(0); i < size - 1; i += 2 {
        sum += uint32(binary.LittleEndian.Uint16(buf[i:i+2]))
	}

	/* Handle odd-sized case */
	if (size % 2 != 0) {
		sum += uint32(buf[len(buf)-1]);
	}

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)

	/* Invert to get the negative in ones-complement arithmetic */
	return uint16(^sum)
}

func ping(addr string) {

    conn, err := net.Dial("ip4:icmp", addr)
    buf := make([]byte, 8, 8)
    buf[0] = 8 // type
    buf[1] = 0 // code
    buf[2] = 0 // checksum 1
    buf[3] = 0 // checksum 2
    buf[4] = 0 // identifier 1
    buf[5] = 0 // identifier 2
    buf[6] = 0 // sequence number 1
    buf[7] = 0 // sequence number 2

    csum := checksum(buf, len(buf));
    buf[3] = byte(csum >> 8);
    buf[2] = byte(csum & 0x00ff);

    if err != nil {
        panic(err.Error())
    }

    for true {
        _, err = conn.Write(buf)
        if err != nil {
            panic(err.Error())
        }
        time.Sleep(1000000000)
    }
}

func doPingProbe(addr string) {
    all, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        panic(err.Error())
    }
    if err != nil {
        panic(err.Error())
    }
    go ping(addr)
    listen, err := net.ListenIP("ip4:icmp", all)
    if err != nil {
        panic(err.Error())
    }
    buf := make([]byte, 20, 20)
    for true {
        _, src, err := listen.ReadFromIP(buf)
        if err != nil {
            panic(err.Error())
        }
        if src.String() == addr {
            fmt.Println("Ping received");
        }
    }
}

func sendSyn(addr string, port uint16) {
    srcport := uint16(rand.Intn(16383) + 49152)
    conn, err := net.Dial("ip4:tcp", addr)
    if err != nil {
        panic(err.Error())
    }

    hdr := TCPHeader {
        SrcPort: srcport,
        DstPort: port,
        Seq: rand.Uint32(),
        Ack: 0,
        HdrSize: 5,
        Flags: 2,
        Window: 1000,
        Checksum: 0,
        Urgent: 0,
    }

    buf := hdr.ToBytesAndCsum(net.ParseIP("192.168.0.49"), net.ParseIP(addr))

    _, err = conn.Write(buf)
    if err != nil {
        panic(err.Error())
    }
}

func IsInMap(m map[uint16]string, val string) bool {
    for _, v := range m {
        if v == val {
            return true
        }
    }
    return false
}

func listenICMP(addr string, c chan uint16) {
    all, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        panic(err.Error())
    }

    listen, err := net.ListenIP("ip4:icmp", all)
    if err != nil {
        panic(err.Error())
    }

    buf := make([]byte, 200, 200)
    for true {
        _, src, err := listen.ReadFromIP(buf)
        if err != nil {
            panic(err.Error())
        }
        if src.String() == addr && buf[0] == 3 && buf[1] == 3 { // destination unreachable / port unreachable
            tcphdr := BytesToTCPHeader(buf[28:])
            c <- tcphdr.DstPort
        }
    }
}

func doSynScan(addr string, ports []string) map[uint16]string {
    states := make(map[uint16]string)
    for _, port := range ports {
        val, err := strconv.Atoi(port)
        if err != nil {
            panic(err.Error())
        }
        states[uint16(val)] = "unknown"
        go sendSyn(addr, uint16(val))
    }

    c := make(chan uint16, 100)

    go listenICMP(addr, c)

    all, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        panic(err.Error())
    }
    listen, err := net.ListenIP("ip4:tcp", all)
    if err != nil {
        panic(err.Error())
    }
    buf := make([]byte, 100, 100)

    start_time := time.Now()
    for IsInMap(states, "unknown") && time.Now().Sub(start_time) < 1e9 {
        _, src, err := listen.ReadFromIP(buf)
        if err != nil {
            panic(err.Error())
        }
        hdr := BytesToTCPHeader(buf)
        if src.String() == addr && states[hdr.SrcPort] == "unknown" {
            if hdr.Flags & 0x12 == 0x12 { // ack / syn
                states[hdr.SrcPort] = "open"
            } else if hdr.Flags & 0x4 == 0x4 { // rst
                states[hdr.SrcPort] = "closed"
            }
        }
        select {
        case p := <-c:
            states[p] = "closed"
        default:
        }
    }

    for len(c) > 0 {
        states[<-c] = "closed"
    }
    for k, v := range states {
        if v == "unknown" {
            states[k] = "filtered"
        }
    }

    return states
}

func main() {
    if len(os.Args) < 3 {
        fmt.Printf("Usage: %s <ip> <ports...>", os.Args[0])
        return
    }
    rand.Seed(int64(time.Now().Nanosecond()))
    states := doSynScan(os.Args[1], os.Args[2:])

    for k, v := range states {
        fmt.Printf(" %5d - %s\n", k, v)
    }
}
