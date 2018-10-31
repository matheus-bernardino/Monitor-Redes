import pyshark

class Sniffer:
    # Tamanho médio dos pacotes
    avgPkg = 0
    # Contador com o número de pacotes
    countPkg = 0
    # Endereço IP de destino mais acessado com o número total de pacotes identificados
    mostAccDst = ["", 0]
    # Endereço IP fonte mais acessado com o número total de pacotes identificados
    mostAccSrc = ["", 0]
    # Dicionário com as chaves equivalentes ao IP de destino e os respectivos conteúdos equivalentes ao número de pacotes 
    ipDst = dict()
    # portDst = dict()
    # Dicionário com as chaves equivalentes ao IP fonte e os respectivos conteúdos equivalentes ao número de pacotes
    ipSrc = dict()
    # portSrc = dict()
    # Dicionário com as chaves equivalentes ao tuple (IP fonte, porta fonte, IP destino, porta destino) e os respectivos conteúdos equivalentes a soma dos tamanho dos pacotes desse fluxo
    flow = dict()

    # Adquire as informações sobre o fluxo de pacotes
    def getFlowInformation(self, packet):
        ipSrc = packet.ip.src
        portSrc = packet[packet.transport_layer].srcport
        ipDst = packet.ip.dst
        portDst = packet[packet.transport_layer].dstport

        # Inicializa o fluxo com o tamanho do primeiro pacote ou faz um incremento nele com o tamanho do pacote atual
        if(self.flow.get((ipSrc, portSrc, ipDst, portDst)) == None):
            self.flow[(ipSrc, portSrc, ipDst, portDst)] = packet.length
        else:
            self.flow[(ipSrc, portSrc, ipDst, portDst)] += packet.length

    # Adquire as informações sobre os pacotes
    def getPacketInformation(self, packet):
        # Incrementa os contadores para calcular a média no fim da execução 
        self.avgPkg += float(packet.length)
        self.countPkg += 1

        # Inicializa os contadores dos IPs fonte ou faz um incremento nele
        if(self.ipSrc.get(packet.ip.src) == None):
            self.ipSrc[packet.ip.src] = 1
        else:    
            self.ipSrc[packet.ip.src] += 1
        # Inicializa os contadores dos IPs de destino ou faz um incremento nele
        if(self.ipDst.get(packet.ip.dst) == None):
            self.ipDst[packet.ip.dst] = 1
        else:    
            self.ipDst[packet.ip.dst] += 1
    # Adquire o endereço IP de destino mais acessado
    def getMostAccessedIp(self, packet):
        # Define o IP atual como o mais acessado junto com o seu número de pacotes se ele for maior que o anterior
        if(self.ipDst[packet.ip.dst] > self.mostAccDst[1]):
            self.mostAccDst = packet.ip.dst, self.ipDst[packet.ip.dst]

    # Faz o mesmo que o método anterior mas para o IP transmissor
    def getMostTransmissorIp(self, packet):
        if(self.ipSrc[packet.ip.src] > self.mostAccSrc[1]):
            self.mostAccSrc = packet.ip.src, self.ipSrc[packet.ip.src]

    # Inicia a captura de pacotes
    def start(self):
        # Intancia o objeto que irá fazer a captura de pacotes na interface de rede definida
        capture = pyshark.LiveCapture(interface='wlp2s0')
        # Atribui 1 segundo ao tempo para capturar os pacotes
        capture.sniff(timeout=1)
        # Inicia a captura de pacotes
        packets = capture._packets
        # Itera por todos os pacotes capturados durante o período de tempo estipulado
        for packet in packets:
            try:
                self.getFlowInformation(packet)
                self.getPacketInformation(packet)
                self.getMostAccessedIp(packet)
                self.getMostTransmissorIp(packet)
     
            except:
                pass

        try:
            # Atribui à avgPkg a média dos pacotes
            self.avgPkg /= self.countPkg
        except:
            pass