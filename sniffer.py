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

    def __init__(self):
        capture = pyshark.LiveCapture(interface='wlp2s0')
        capture.sniff(timeout=5)
        packets = capture._packets
        for packet in packets:
            try:
                #print (packet)
                self.getFlowInformation(packet)
                self.getPacketInformation(packet)
                self.getMostAccessedIp(packet)
                self.getMostTransmissorIp(packet)
                # # print dir(packet.my_layer())
                # # print (packet.length)
                # try:
                #     # if(ipDst.get(packet.ip.dst) == None):
                #     #     ipDst[packet.ip.dst] = 1
                #     # else:    
                #     ipDst[packet.ip.dst]+=1
                #     # if(ipSrc.get(packet.ip.src) == None):
                #         # ipSrc[packet.ip.src] = 1
                #     # else:    
                #     ipSrc[packet.ip.src]+=1

                #     if(portDst.get(packet[packet.transport_layer].dstport) == None):
                #         portDst[packet[packet.transport_layer].dstport] = 1
                #     else:    
                #         portDst[packet[packet.transport_layer].dstport]+=1
                #     if(portSrc.get(packet[packet.transport_layer].srcport) == None):
                #         portSrc[packet[packet.transport_layer].srcport] = 1
                #     else:    
                #         portSrc[packet[packet.transport_layer].srcport]+=1

                #     if(ipDst[packet.ip.dst] > mostAccDst[1]):
                #         mostAccDst = packet.ip.dst, ipDst[packet.ip.dst]
                #     if(ipSrc[packet.ip.src] > mostAccSrc[1]):
                #         mostAccSrc = packet.ip.src, ipSrc[packet.ip.src]
                    
                #     avgPkg += float(packet.length)
                #     countPkg+=1
                #     # print (packet.ip.dst, ": ", ipDst[packet.ip.dst])
                #     # print (packet.ip.src, ": ", ipSrc[packet.ip.src])
                #     # print (packet[packet.transport_layer])
                #     # print (packet[packet.transport_layer].srcport)
                #     # print (packet[packet.transport_layer].dstport)
                #     # print (packet.port.src)
                # except:
                #     pass
            except:
                pass

        try:
            self.avgPkg /= self.countPkg
        except:
            pass

        print ('Fluxo: ', self.flow)
        print ('Número de pacotes:', self.countPkg)
        print ("Média do tamanho dos pacotes: ", self.avgPkg)
        print ("IP de destino mais acessado: ", self.mostAccDst)
        print ("IP de origem mais acessado: ", self.mostAccSrc)
        print ("IPs de destino: ", self.ipDst)
        print ("IPs de origem: ", self.ipSrc)

sniffer = Sniffer()