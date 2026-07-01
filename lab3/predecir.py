#!/usr/bin/env python3
"""
predecir.py
------------
Examen Final - Seguridad Informatica - Unidad IV
Laboratorio 3 - Tarea 3.4: Exportacion y uso del modelo
Autor: Alex Coila Jarita
 
Carga modelo_anomalias.pkl y clasifica un archivo CSV nuevo con la misma
estructura de columnas que network_traffic.csv (sin necesidad de la
columna label).
 
Uso:
    python predecir.py nuevo_trafico.csv
"""
 
import sys
from pathlib import Path
 
import joblib
import numpy as np
import pandas as pd
 
MODELO_PATH = Path("modelo_anomalias.pkl")
 
 
def construir_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (df["duration_sec"] + 1)
    # Misma transformacion log1p aplicada durante el entrenamiento (ver
    # deteccion_anomalias.ipynb, Tarea 3.1): es indispensable usar
    # exactamente el mismo preprocesamiento al predecir, o el modelo
    # recibira features en una escala distinta a la que aprendio.
    for col in ["bytes_sent", "bytes_recv", "ratio_bytes", "bytes_por_segundo"]:
        df[col + "_log"] = np.log1p(df[col])
    return df
 
 
def main():
    if len(sys.argv) != 2:
        print("Uso: python predecir.py <archivo_csv>")
        sys.exit(1)
 
    archivo_entrada = Path(sys.argv[1])
    if not archivo_entrada.exists():
        print(f"Error: no se encontro el archivo {archivo_entrada}")
        sys.exit(1)
 
    if not MODELO_PATH.exists():
        print(f"Error: no se encontro {MODELO_PATH}. Ejecute primero el notebook "
              f"deteccion_anomalias.ipynb (Tarea 3.4) para generarlo.")
        sys.exit(1)
 
    paquete = joblib.load(MODELO_PATH)
    modelo = paquete["modelo"]
    scaler = paquete["scaler"]
    features = paquete["features"]
 
    df = pd.read_csv(archivo_entrada, parse_dates=["timestamp"])
    df = construir_features(df)
 
    X = pd.DataFrame(scaler.transform(df[features]), columns=features)
    df["prediccion"] = modelo.predict(X)
    df["score_anomalia"] = modelo.decision_function(X)
    df["prediccion_label"] = df["prediccion"].map({1: "normal", -1: "anomaly"})
 
    anomalias = df[df["prediccion_label"] == "anomaly"].sort_values("score_anomalia")
 
    print(f"Registros analizados: {len(df)}")
    print(f"Anomalias detectadas: {len(anomalias)}\n")
 
    if len(anomalias) == 0:
        print("No se detectaron anomalias en el archivo proporcionado.")
        return
 
    print("=== Registros clasificados como anomalia ===")
    columnas_mostrar = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                         "bytes_sent", "bytes_recv", "duration_sec", "score_anomalia"]
    columnas_mostrar = [c for c in columnas_mostrar if c in anomalias.columns]
    for _, fila in anomalias.iterrows():
        valores = " | ".join(f"{c}={fila[c]}" for c in columnas_mostrar)
        print(f"[ANOMALIA] {valores}")
 
 
if __name__ == "__main__":
    main()
