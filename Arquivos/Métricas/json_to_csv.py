#!/usr/bin/env python3

import json
import pandas as pd
import sys

def json_to_csv(json_filename, csv_filename):
    try:
        # Abre o arquivo JSON e carrega os dados
        with open(json_filename, 'r') as json_file:
            data = json.load(json_file)

        # Extrai os dados relevantes do JSON
        intervals = data.get('intervals', [])
        rows = []

        for interval in intervals:
            for stream in interval.get('streams', []):
                row = {
                    'start': interval.get('sum', {}).get('start', 0),
                    'bits_per_second': stream.get('bits_per_second', 0)
                }
                rows.append(row)

        # Cria um DataFrame do Pandas
        df = pd.DataFrame(rows)

        # Salva apenas as colunas 'start' e 'bits_per_second' no arquivo CSV
        df[['start', 'bits_per_second']].to_csv(csv_filename, index=False)
        print(f"Arquivo CSV '{csv_filename}' gerado com sucesso a partir de '{json_filename}'.")

    except FileNotFoundError:
        print(f"Erro: O arquivo '{json_filename}' não foi encontrado.")
    except json.JSONDecodeError:
        print(f"Erro: O arquivo '{json_filename}' não é um JSON válido.")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 json_to_csv.py <arquivo_json> <arquivo_csv>")
        sys.exit(1)

    json_filename = sys.argv[1]
    csv_filename = sys.argv[2]

    json_to_csv(json_filename, csv_filename)
