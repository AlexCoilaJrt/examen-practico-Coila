#!/usr/bin/env python3
"""
visualizar.py
--------------
Examen Final - Seguridad Informatica - Unidad IV
Laboratorio 1 - Tarea 1.3: Visualizacion
Autor: Alex Coila Jarita

Genera tres graficas a partir de reporte_ssh.json y access.log:
  1. Barras: Top 10 IPs con mas intentos fallidos SSH.
  2. Linea de tiempo: peticiones HTTP por hora.
  3. Mapa de calor: peticiones HTTP por hora y codigo de respuesta.

Requiere: pip install matplotlib seaborn pandas --break-system-packages
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

REPORTE_SSH = Path("reporte_ssh.json")
ACCESS_LOG = Path("access.log")
SALIDA = Path("graficas")
SALIDA.mkdir(exist_ok=True)

PATRON_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<url>.+?) HTTP/\d\.\d" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)
FORMATO_FECHA_APACHE = "%d/%b/%Y:%H:%M:%S %z"


def cargar_top10_ssh():
    with REPORTE_SSH.open(encoding="utf-8") as f:
        data = json.load(f)
    ips = [item["ip"] for item in data["ips_sospechosas"][:10]]
    intentos = [item["intentos"] for item in data["ips_sospechosas"][:10]]
    return ips, intentos


def cargar_eventos_web():
    eventos = []
    with ACCESS_LOG.open(encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = PATRON_CLF.search(linea)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("fecha"), FORMATO_FECHA_APACHE)
            except ValueError:
                continue
            eventos.append({"timestamp": ts, "status": int(m.group("status"))})
    return pd.DataFrame(eventos)


def grafico_top10_ssh(ips, intentos):
    plt.figure(figsize=(10, 6))
    sns.barplot(x=intentos, y=ips, hue=ips, palette="Reds_r", legend=False)
    plt.title("Top 10 IPs con mas intentos fallidos SSH", fontsize=14, fontweight="bold")
    plt.xlabel("Intentos fallidos")
    plt.ylabel("Direccion IP")
    plt.tight_layout()
    plt.savefig(SALIDA / "top10_ssh.png", dpi=150)
    plt.close()
    print(f"Generado: {SALIDA / 'top10_ssh.png'}")


def grafico_timeline_http(df: pd.DataFrame):
    df["hora"] = df["timestamp"].dt.floor("h")
    serie = df.groupby("hora").size()
    plt.figure(figsize=(12, 5))
    serie.plot(kind="line", marker="o", color="#2E75B6")
    plt.title("Peticiones HTTP por hora", fontsize=14, fontweight="bold")
    plt.xlabel("Hora")
    plt.ylabel("Numero de peticiones")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(SALIDA / "timeline_http.png", dpi=150)
    plt.close()
    print(f"Generado: {SALIDA / 'timeline_http.png'}")


def grafico_heatmap_http(df: pd.DataFrame):
    df["hora_del_dia"] = df["timestamp"].dt.hour
    codigos_interes = [200, 301, 404, 500]
    df_filtrado = df[df["status"].isin(codigos_interes)]
    tabla = pd.crosstab(df_filtrado["hora_del_dia"], df_filtrado["status"])
    tabla = tabla.reindex(columns=codigos_interes, fill_value=0)

    plt.figure(figsize=(8, 8))
    sns.heatmap(tabla, annot=True, fmt="d", cmap="YlOrRd", linewidths=0.5)
    plt.title("Peticiones HTTP por hora y codigo de respuesta", fontsize=14, fontweight="bold")
    plt.xlabel("Codigo de respuesta")
    plt.ylabel("Hora del dia")
    plt.tight_layout()
    plt.savefig(SALIDA / "heatmap_http.png", dpi=150)
    plt.close()
    print(f"Generado: {SALIDA / 'heatmap_http.png'}")


def main():
    ips, intentos = cargar_top10_ssh()
    grafico_top10_ssh(ips, intentos)

    df = cargar_eventos_web()
    grafico_timeline_http(df)
    grafico_heatmap_http(df)

    print("\nLas 3 graficas fueron guardadas en la carpeta graficas/")


if __name__ == "__main__":
    main()
