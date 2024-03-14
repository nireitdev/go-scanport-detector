package traffic

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/context"
	"log"
	"strings"
)

type ScanInfo struct {
	IPorigin  string
	Portlocal string
	Proto     string
}
type ConfigPcap struct {
	Ctx        context.Context
	Device     string
	Ip         string
	Portrange  string
	Portignore string
}

var ChanInfo chan ScanInfo

func NewCapture(cnf ConfigPcap) chan ScanInfo {
	ChanInfo = make(chan ScanInfo)
	go cnf.capture()
	return ChanInfo
}

func (conf *ConfigPcap) capture() {

	// Inicio captura de trafico:
	handle, err := pcap.OpenLive(conf.Device, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		handle.Close()
		close(ChanInfo)
	}()

	//Creo el filtro de trafico:
	ports := strings.Join(strings.Split(conf.Portignore, ","), " and not port ")
	filter := fmt.Sprintf(" dst host %s and not src host %s and portrange %s and not port %s",
		conf.Ip, conf.Ip,
		conf.Portrange, ports)

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Starting...")
	//log.Printf("Filter: %s \n", filter)

	//Capturo paquetes y analizo si es ip, tcp /udp.
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var tcpLayer layers.TCP
	var udpLayer layers.UDP

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//@TODO: ctx?? debo poner el ctx para cortar esta go-routine.

	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
			&udpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			//algun protocolo que no me interesa analizar
			//log.Println("Trouble decoding layers: ", err)
		}

		var ipsrc, portdst, proto string
		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				//ipLayer.SrcIP, ipLayer.DstIP
				ipsrc = ipLayer.SrcIP.String()
			}
			if layerType == layers.LayerTypeTCP {
				//tcpLayer.SrcPort, tcpLayer.DstPort
				//tcpLayer.SYN, tcpLayer.ACK)
				portdst = tcpLayer.DstPort.String()
				proto = "TCP"
			}
			if layerType == layers.LayerTypeUDP {
				//udpLayer.SrcPort, udpLayer.DstPort
				portdst = udpLayer.DstPort.String()
				proto = "UDP"

			}

		}

		ChanInfo <- ScanInfo{IPorigin: ipsrc, Portlocal: portdst, Proto: proto}

	}
}
