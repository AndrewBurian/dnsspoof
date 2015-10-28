package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

func getIfaceAddr(ifacename string) net.IP {

	// get the list of interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// loop through them to get our local address
	for i := range ifaces {

		// check it's the interface we want
		if ifaces[i].Name != ifacename {
			continue
		}

		// get the addresses
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			panic(err)
		}

		// check to ensure there is an address on this interface
		if len(addrs) < 1 {
			panic("No address on target interface")
		}

		// use the first available address
		ip, _, err := net.ParseCIDR(addrs[0].String())
		if err != nil {
			panic(err)
		}

		return ip

	}
	return nil
}

/*
Spoof is the entry point for the actual spoofing subroutine.

Spoof handles getting packets from the NICs, identifying DNS
queries, and seding responses. It is mostly concerened with
the packet level logic, and does not manipulate the responses
themselves
*/
func spoof(ifacename string) {

	// get our local ip
	ip := getIfaceAddr(ifacename)
	if ip == nil {
		panic("Unable to get IP")
	}

	// open a handle to the network card(s)
	handle, err := pcap.OpenLive(ifacename, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// set the filter
	err = handle.SetBPFFilter("dst port 53")
	if err != nil {
		// not fatal
		fmt.Printf("Unable to set filter: %v\n", err.Error())
	}

	// get the channel source from the card
	pktSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Main loop for dns packets intercepted
	for packet := range pktSource.Packets() {

		// attempt to get a DNS layer out of this packet
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue;
		}

		// get the DNS data from this layer by type assertion
		dnsPkt := dnsLayer.(*layers.DNS)

		// check that this is not a response
		if dnsPkt.QR {
			continue;
		}

		// print the data
		fmt.Println(dnsPkt)
	}
}
