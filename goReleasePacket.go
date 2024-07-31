package main

// from : https://byteshiva.medium.com/how-to-read-and-extract-information-from-a-pcap-file-in-go-287c0bd66561

// A simple pcap for goRelease
//

import (
	"fmt"                               // Import the fmt package to print messages to the console.
	"github.com/google/gopacket"        // Import the gopacket package to decode packets.
	"github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
	"github.com/google/gopacket/pcap"   // Import the pcap package to capture packets.
	"log"                               // Import the log package to log errors to the console.
	"os"
	"time"
)

var (
	device       string        = "en0"
	snapshot_len int32         = 0
	promiscuous  bool          = true
	timeout      time.Duration = 1 * time.Second
)

func main() {
	// Check if file argument is provided
	if len(os.Args) < 2 {
		fmt.Println("Please provide a pcap file to read")
		os.Exit(1)
	}

	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// Print the packet details
		fmt.Println(packet.String())

		// Extract and print the Ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			ethPacket, _ := ethLayer.(*layers.Ethernet)
			fmt.Println("Ethernet source MAC address:", ethPacket.SrcMAC)
			fmt.Println("Ethernet destination MAC address:", ethPacket.DstMAC)
		}

		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ipPacket, _ := ipLayer.(*layers.IPv4)
			fmt.Println("IP source address:", ipPacket.SrcIP)
			fmt.Println("IP destination address:", ipPacket.DstIP)
		}
	}
}
