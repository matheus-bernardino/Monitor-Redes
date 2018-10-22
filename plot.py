import matplotlib.pyplot as plt

# Plota as tabelas com os resultados do monitoramento:
class Plot:
    def dino_plot(self, Sniffer):
        # Configuração do plot dos fluxos identificados
        fig = plt.figure(0)
        fig.patch.set_visible(False)
        plt.axis('off')
        plt.title('Flows identified')

        # Títulos das colunas
        columns = ('Source IP', 'Source Port', 'Destination IP',
                   'Destination Port', 'Data Transmitted in Bytes')

        # Insere os dados nas células da tabela
        cell_text = []
        for key in Sniffer.flow:
            cell_text.append(
                [key[0], key[1], key[2], key[3], Sniffer.flow[key] + ' Bytes'])

        try:
            # Configura a tabela
            tb = plt.table(cellText=cell_text,
                    colLabels=columns,
                    loc='center')
            fig.tight_layout()

            tb.auto_set_font_size(False)
            tb.set_fontsize(6)
        except:
            pass

        
        # Faz a mesma configuração do plot acima para as informações gerais
        fig = plt.figure(1)
        fig.patch.set_visible(False)
        plt.axis('off')
        plt.title('General Information')

        columns = ('Number of Packets', 'Average Packets Size', 'Destination IP Most Accesd',
                   'Source IP Most Accesd')
        
        
        cell_text = []
        cell_text.append(
                [Sniffer.countPkg, Sniffer.avgPkg, Sniffer.mostAccDst[0], Sniffer.mostAccSrc[0]])

        try:
            tb = plt.table(cellText=cell_text,
                    colLabels=columns,
                    loc='center')
            fig.tight_layout()

            tb.auto_set_font_size(False)
            tb.set_fontsize(6)
        except:
            pass

        # Plota ambos os gráficos
        if(Sniffer.countPkg > 0):
            plt.show()
        else:
            print('Nenhum pacote capturado')