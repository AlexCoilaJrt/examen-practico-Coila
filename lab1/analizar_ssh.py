#!/usr/bin/env python3
"""
analizar_ssh.py
----------------
Examen Final - Seguridad Informatica - Unidad IV
Laboratorio 1 - Tarea 1.1: Parseo y estadisticas de auth.log
Autor: Alex Coila Jarita

Lee lab1/auth.log, identifica intentos de autenticacion SSH fallidos
("Failed password"), cuenta los intentos por IP de origen, genera un
ranking Top 10, emite alertas en consola para IPs con mas de 50 intentos
y exporta el resultado a reporte_ssh.json.
"""

import re
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("auth.log")
REPORT_PATH = Path("reporte_ssh.json")
UMBRAL_ALERTA = 50

# Coincide con lineas tipo:
#   Mar 15 02:14:23 server sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
#   Mar 15 02:14:23 server sshd[12345]: Failed password for root from 203.0.113.45 port 51234 ssh2
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def leer_log(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(
            f"No se encontro {path}. Copie auth.log a la carpeta lab1/ antes de ejecutar."
        )
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def contar_intentos_fallidos(lineas: list[str]) -> Counter:
    contador = Counter()
    for linea in lineas:
        match = PATRON_FALLO.search(linea)
        if match:
            contador[match.group("ip")] += 1
    return contador


def generar_alertas(contador: Counter) -> list[dict]:
    ips_sospechosas = []
    for ip, intentos in contador.most_common():
        alerta = intentos > UMBRAL_ALERTA
        if alerta:
            print(f"[ALERTA] IP: {ip} - {intentos} intentos fallidos - Posible ataque de fuerza bruta")
        ips_sospechosas.append({"ip": ip, "intentos": intentos, "alerta": alerta})
    return ips_sospechosas


def main():
    lineas = leer_log(LOG_PATH)
    contador = contar_intentos_fallidos(lineas)
    total_fallidos = sum(contador.values())

    print(f"Total de lineas analizadas: {len(lineas)}")
    print(f"Total de intentos fallidos detectados: {total_fallidos}")
    print(f"IPs distintas con intentos fallidos: {len(contador)}\n")

    print("=== Top 10 IPs con mas intentos fallidos ===")
    for posicion, (ip, intentos) in enumerate(contador.most_common(10), start=1):
        print(f"{posicion:>2}. {ip:<15} -> {intentos} intentos")
    print()

    print("=== Verificacion de umbral de fuerza bruta (>50 intentos) ===")
    ips_sospechosas = generar_alertas(contador)

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": sorted(
            ips_sospechosas, key=lambda x: x["intentos"], reverse=True
        )[:10],
    }

    with REPORT_PATH.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado a {REPORT_PATH.resolve()}")


if __name__ == "__main__":
    main()
