import pyshark

class Sniffer:
    avgPkg = 0
    countPkg = 0
    mostAccDst = ["", 0]
    mostAccSrc = ["", 0] 
    ipDst = dict()
    portDst = dict()
    ipSrc = dict()
    portSrc = dict()
    flow = dict()

    def getFlowInformation(self, packet):
        ipSrc = packet.ip.src
        portSrc = packet[packet.transport_layer].srcport
        ipDst = packet.ip.dst
        portDst = packet[packet.transport_layer].dstport

        if(self.flow.get((ipSrc, portSrc, ipDst, portDst)) == None):
            self.flow[(ipSrc, portSrc, ipDst, portDst)] = packet.length
        else:
            self.flow[(ipSrc, portSrc, ipDst, portDst)] += packet.length

    def getPacketInformation(self, packet):
        self.avgPkg += float(packet.length)
        self.countPkg += 1

        if(self.ipSrc.get(packet.ip.src) == None):
            self.ipSrc[packet.ip.src] = 1
        else:    
            self.ipSrc[packet.ip.src] += 1
        if(self.ipDst.get(packet.ip.dst) == None):
            self.ipDst[packet.ip.dst] = 1
        else:    
            self.ipDst[packet.ip.dst] += 1

    def getMostAccessedIp(self, packet):
        if(self.ipDst[packet.ip.dst] > self.mostAccDst[1]):
            self.mostAccDst = packet.ip.dst, self.ipDst[packet.ip.dst]

    def getMostTransmissorIp(self, packet):
        if(self.ipSrc[packet.ip.src] > self.mostAccSrc[1]):
            self.mostAccSrc = packet.ip.src, self.ipSrc[packet.ip.src]

    def start(self):
        capture = pyshark.LiveCapture(interface='wlp2s0')
        capture.sniff(timeout=1)
        packets = capture._packets
        for packet in packets:
            try:
                self.getFlowInformation(packet)
                self.getPacketInformation(packet)
                self.getMostAccessedIp(packet)
                self.getMostTransmissorIp(packet)
     
            except:
                pass

        try:
            self.avgPkg /= self.countPkg
        except:
            pass

        # print ('Fluxo: ', self.flow)
        # print ('Número de pacotes:', self.countPkg)
        # print ("Média do tamanho dos pacotes: ", self.avgPkg)
        # print ("IP de destino mais acessado: ", self.mostAccDst)
        # print ("IP de origem mais acessado: ", self.mostAccSrc)
        # print ("IPs de destino: ", self.ipDst)
        # print ("IPs de origem: ", self.ipSrc)