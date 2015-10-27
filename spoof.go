package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/*
Spoof is the entry point for the actual spoofing subroutine.

Spoof handles getting packets from the NICs, identifying DNS
queries, and seding responses. It is mostly concerened with
the packet level logic, and does not manipulate the responses
themselves
*/
func spoof() {
	// open a handle to the network card(s)
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
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
