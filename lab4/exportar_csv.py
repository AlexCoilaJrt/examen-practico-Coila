import json
import pandas as pd

with open('/tmp/alertas_muestra.json') as f:
    data = json.load(f)

hits = [h['_source'] for h in data['hits']['hits']]
df = pd.json_normalize(hits)
df.to_csv('/home/alexserver/examen-practico-coila/lab4/alertas_muestra.csv', index=False)
print(f'{len(df)} registros exportados a lab4/alertas_muestra.csv')
