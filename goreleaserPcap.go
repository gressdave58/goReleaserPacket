package main

// from : https://byteshiva.medium.com/how-to-read-and-extract-information-from-a-pcap-file-in-go-287c0bd66561

// test build
//

import (
    "os"
    "fmt"                   // Import the fmt package to print messages to the console.
    "log"                   // Import the log package to log errors to the console.
    "time"
    "github.com/google/gopacket/pcap" // Import the pcap package to capture packets.
    "github.com/google/gopacket/pcapgo"
    "github.com/google/gopacket" // Import the gopacket package to decode packets.

    "github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
)

var (
        device         string = "en0"
snapshot_len   int32  = 0	
 promiscuous    bool   = true
timeout        time.Duration = 1 * time.Second

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


func RunPacketCapture(DsourceHandle *pcap.Handle, outputFileName string, MaxPackets int, MaxTime int) {
        sourceHandle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
        if err != nil {
                fmt.Println("Failed to create packet capture handle")
                return
        }
        defer sourceHandle.Close()

        fmt.Println("RunPacketCapture .. enter:", outputFileName, ":", MaxPackets, ":", MaxTime)
        if err := sourceHandle.SetBPFFilter("tcp"); err != nil {
                fmt.Println("Failed to set BPF filter")
                return
        }
        now := time.Now()               
        unixMilli := now.UnixMilli()
        outputFilename := fmt.Sprintf("./captures/%s-%d.pcap", outputFileName, unixMilli)
        outputFile, err := os.Create(outputFilename)
        if err != nil {                    
                fmt.Println("Failed to craete packet capture output file", "err", err, "filename", outputFilename)
                return
        }
        defer func(outputFile *os.File) {
        if err := outputFile.Close(); err != nil {
          fmt.Println("Failed to close file:", outputFileName, err)
        }
        }(outputFile)
        
        outputWriter := pcapgo.NewWriter(outputFile)
        if err := outputWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
                fmt.Println("Failed to write file header:", outputFileName, err)
                return
        }

}
