from sniffer import Sniffer
from plot import Plot

def main():
    sniffer = Sniffer()   
    sniffer.start()
    plt = Plot()
    plt.dino_plot(sniffer)


if __name__ == '__main__':
    main()
