#!/bin/bash

# Definindo o número de repetições
repeticoes=3

# Loop para repetir o processo
for i in $(seq 1 $repeticoes)
do
    echo "Aguardando 1 minuto antes de iniciar a execução do iperf (repetição $i)..."
    sleep 60
    
    echo "Executando iperf na repetição $i..."
    iperf3 -c 10.30.0.3 -t 120 -P 8 -B 10.30.0.11
    
    echo "Repetição $i concluída!"
done

echo "Aguardando 1 minuto para finalizar..."
sleep 60

echo "Execução do script concluída!"

