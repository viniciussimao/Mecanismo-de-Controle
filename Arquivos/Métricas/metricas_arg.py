#!/usr/bin/env python3

import pandas as pd
import argparse

def calcular_delay_jitter(arquivo):
    # Definindo as colunas
    colunas = [
        "cpu_usage", "mem_usage", "timestamp",
        "switchID_t_3", "ingress_port_3", "egress_port_3", "egress_spec_3",
        "ingress_global_timestamp_3", "egress_global_timestamp_3", "enq_timestamp_3",
        "enq_qdepth_3", "deq_timedelta_3", "deq_qdepth_3", 
        "switchID_t_2", "ingress_port_2", "egress_port_2", "egress_spec_2",
        "ingress_global_timestamp_2", "egress_global_timestamp_2", "enq_timestamp_2",
        "enq_qdepth_2", "deq_timedelta_2", "deq_qdepth_2",
        "switchID_t_1", "ingress_port_1", "egress_port_1", "egress_spec_1",
        "ingress_global_timestamp_1", "egress_global_timestamp_1", "enq_timestamp_1",
        "enq_qdepth_1", "deq_timedelta_1", "deq_qdepth_1" 
    ]
    
    # Carregar os dados, ignorando a primeira linha
    dados = pd.read_csv(arquivo, header=None, names=colunas)

    # Remover espaços em branco das colunas
    dados.columns = dados.columns.str.strip()
    
    # Verificar se existem dados inválidos nas colunas de timestamp
    dados['timestamp'] = dados['timestamp'].astype(str).str.strip()
    dados['ingress_global_timestamp_1'] = dados['ingress_global_timestamp_1'].astype(str).str.strip()
    dados['egress_global_timestamp_3'] = dados['egress_global_timestamp_3'].astype(str).str.strip()

    # Converter as colunas de timestamp para inteiro
    dados['timestamp'] = pd.to_numeric(dados['timestamp'], errors='coerce')
    dados['ingress_global_timestamp_1'] = pd.to_numeric(dados['ingress_global_timestamp_1'], errors='coerce')
    dados['egress_global_timestamp_3'] = pd.to_numeric(dados['egress_global_timestamp_3'], errors='coerce')

    # Calcular o delay para cada linha
    dados['delay'] = (dados['egress_global_timestamp_3'] - dados['timestamp']) / 1e3
#    dados['delay'] = (dados['egress_global_timestamp_3'] - dados['ingress_global_timestamp_1']) / 1e3
    
    # Calcular o jitter para cada pacote
    dados['jitter'] = dados['delay'].rolling(window=2).apply(lambda x: x.std(), raw=False)
    
    # Calcular o delay e jitter médios
    delay_medio = dados['delay'].mean()
    jitter_medio = dados['jitter'].mean()

    # Exibir os resultados com linhas em branco
    print(f"\nDelay médio: {delay_medio:.3f} ms\n")
    print(f"Jitter médio: {jitter_medio:.3f} ms\n")
    
    # Retornar os delays e jitters
    return dados[['delay', 'jitter']]

# Exemplo de uso
if __name__ == "__main__":
    # Configurar o argumento de linha de comando para o arquivo
    parser = argparse.ArgumentParser(description="Calcular delay e jitter a partir de um arquivo de dados.")
    parser.add_argument('arquivo', type=str, help="Caminho do arquivo de dados")
    
    args = parser.parse_args()
    
    # Chamar a função com o arquivo especificado
    resultados = calcular_delay_jitter(args.arquivo)
    
    print("Resultados (delay e jitter de cada pacote) em milissegundos:")
    print(resultados)

