from sniffer import Sniffer
from plot import Plot

# Faz a captura dos pacote e depois plota os dados dos pacotes capturados
def main():
    sniffer = Sniffer()   
    sniffer.start()
    plt = Plot()
    plt.plotTables(sniffer)


if __name__ == '__main__':
    main()
