#!/bin/bash

# Adicionando entradas de ARP
sudo ip neigh add 10.30.0.2 lladdr 00:0c:29:d6:11:4f dev ens36
sudo ip neigh add 10.30.0.3 lladdr 00:0c:29:29:1a:9a dev ens36

# Desabilitando offload
sudo ethtool --offload ens36 gso off tso off gro off

# Verificando as entradas ARP
ARP_TABLE=$(ip neigh show)

# Checando se há alguma entrada com o status FAILED
if echo "$ARP_TABLE" | grep -q "FAILED"; then
  # Deletando a entrada com FAILED
  echo "$ARP_TABLE" | grep "FAILED" | while read line; do
    IP_ADDRESS=$(echo $line | awk '{print $1}')
    sudo ip neigh del $IP_ADDRESS dev ens36
    # Re-adicionando a entrada
    sudo ip neigh add $IP_ADDRESS lladdr $(echo $line | awk '{print $5}') dev ens36
  done
fi

# Adicionando IP na Rede 5G
sudo ip addr add 10.60.0.100/16 dev upfgtp

# Exibindo a tabela ARP após as alterações
ip neigh show

