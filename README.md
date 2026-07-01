# examen-practico-coila

**Autor:** Alex Coila Jarita
**Curso:** Seguridad Informática — Ciclo IX — Unidad IV
**Escuela Profesional:** Ingeniería de Sistemas
**Evaluación:** Práctica Final — Monitoreo de Seguridad, SIEM e Inteligencia Artificial

Repositorio con el desarrollo de los cuatro laboratorios: análisis forense de logs con Python, reglas de correlación en Wazuh, modelo de detección de anomalías con Machine Learning y dashboard de monitoreo SOC.

---

## 1. Arquitectura del laboratorio

Entorno 100% local sobre Oracle VirtualBox, con dos máquinas virtuales conectadas a la misma Red NAT (NatNetwork), lo que permite conectividad entre ellas y acceso a internet.

| VM | Rol | SO | IP real |
|----|-----|----|---------|
| VM1-SIEM | Wazuh (Manager + Indexer + Dashboard) + Python/Jupyter | Ubuntu Server 24.04 LTS | 10.0.2.3 |
| Kali-Atacante | Máquina ofensiva (opcional) | Kali Linux 2024.x | 10.0.2.4 |

La guía usaba 192.168.56.10 como IP de ejemplo; el entorno real quedó en el rango 10.0.2.x asignado por DHCP de la Red NAT. La conectividad entre VMs se verificó con ping (0% packet loss).

Acceso al Wazuh Dashboard desde el equipo anfitrión (Windows) vía reenvío de puertos de VirtualBox: https://127.0.0.1:8443 hacia 10.0.2.3:443. También se configuró reenvío para SSH (2222 a 22) y Jupyter (8888 a 8888).

---

## 2. Entorno y versiones

| Componente | Versión / Detalle |
|------------|-------------------|
| Sistema operativo | Ubuntu Server 24.04 LTS |
| Wazuh | v4.9.2 (instalación all-in-one) |
| Python | 3.12 (entorno virtual ~/venv-examen) |
| Librerías Python | pandas, numpy, scikit-learn, matplotlib, seaborn, joblib, jupyter |
| Herramienta de dashboard | Wazuh Dashboard (OpenSearch Dashboards integrado) |

### Comandos de configuración del entorno

    sudo apt update && sudo apt upgrade -y
    sudo apt install -y python3 python3-pip python3-venv libxml2-utils
    python3 -m venv ~/venv-examen
    source ~/venv-examen/bin/activate
    pip install pandas numpy scikit-learn matplotlib seaborn joblib jupyter
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
    sudo bash ./wazuh-install.sh -a
    sudo ufw allow 22/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 8888/tcp
    sudo ufw allow 1514/tcp 1515/tcp 55000/tcp
    sudo ufw reload

---

## 3. Estructura del repositorio

    examen-practico-coila/
    ├── README.md
    ├── lab1/
    │   ├── analizar_ssh.py
    │   ├── analizar_web.py
    │   ├── visualizar.py
    │   ├── auth.log
    │   ├── access.log
    │   ├── reporte_ssh.json
    │   ├── reporte_web.json
    │   ├── graficas/ (top10_ssh.png, timeline_http.png, heatmap_http.png)
    │   └── evidencias/ (SCR-1.1a, SCR-1.1b, SCR-1.2a, SCR-1.2b)
    ├── lab2/
    │   ├── local_rules_ssh.xml
    │   ├── local_rules_exfil.xml
    │   ├── simular_bruteforce.sh
    │   └── evidencias/ (SCR-2.1, SCR-2.2, SCR-2.3)
    ├── lab3/
    │   ├── deteccion_anomalias.ipynb
    │   ├── predecir.py
    │   ├── network_traffic.csv
    │   ├── modelo_anomalias.pkl
    │   ├── nuevo_trafico.csv
    │   └── evidencias/ (SCR-3.1, SCR-3.2, SCR-3.3, SCR-3.4)
    └── lab4/
        ├── dashboard_soc.json
        ├── alertas_muestra.csv
        ├── exportar_csv.py
        └── evidencias/ (SCR-4.1, SCR-4.2, SCR-4.3, SCR-4.4)

---

## 4. Reproducción de cada laboratorio

Los datasets provienen del repositorio oficial del curso: https://github.com/abelthf/examen_final_seguridad_informatica

    git clone --depth 1 https://github.com/abelthf/examen_final_seguridad_informatica.git /tmp/curso
    cp /tmp/curso/lab1/auth.log        lab1/auth.log
    cp /tmp/curso/lab1/access.log      lab1/access.log
    cp /tmp/curso/lab2/simular_bruteforce.sh lab2/simular_bruteforce.sh
    cp /tmp/curso/lab3/network_traffic.csv   lab3/network_traffic.csv

### Laboratorio 1 — Análisis forense de logs (Python)

    source ~/venv-examen/bin/activate
    cd lab1
    python3 analizar_ssh.py
    python3 analizar_web.py
    python3 visualizar.py

Resultados: 253 intentos SSH fallidos, 2 IPs sobre el umbral de fuerza bruta (45.33.32.156 con 120, 193.32.162.55 con 58) y 24 intentos de SQL Injection detectados.

### Laboratorio 2 — Reglas de correlación en Wazuh

    sudo cp lab2/local_rules_ssh.xml   /var/ossec/etc/rules/
    sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/
    sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo OK
    sudo xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo OK
    sudo systemctl restart wazuh-manager
    sudo bash lab2/simular_bruteforce.sh 203.0.113.50 15
    sudo grep "Ataque de fuerza bruta SSH" /var/ossec/logs/alerts/alerts.log | tail

Notas de configuración importantes:
- Se añadió /var/log/auth.log como fuente de logs en /var/ossec/etc/ossec.conf (la instalación por defecto solo leía journald).
- La regla 100001 se basa en if_sid 5763 (regla nativa de brute force de Wazuh 4.9.2), ya que en esta versión los fallos SSH escalan por la 5760 a 5763.
- La regla 100001 se disparó correctamente (nivel 10) con la IP 203.0.113.50.

### Laboratorio 3 — Modelo de detección de anomalías (ML)

    source ~/venv-examen/bin/activate
    cd lab3
    jupyter notebook --no-browser --port=8888 --ip=0.0.0.0
    python3 predecir.py nuevo_trafico.csv

Resultados: Isolation Forest con F1-Score de 0.802 (umbral por defecto) y 0.876 (umbral óptimo -0.0531). Se aplicó transformación logarítmica (log1p) a las variables de bytes para mejorar la separación de clases. Modelo exportado como modelo_anomalias.pkl.

### Laboratorio 4 — Dashboard de monitoreo SOC

Herramienta: Wazuh Dashboard (OpenSearch Dashboards), accesible en https://127.0.0.1:8443
- Index pattern: wazuh-alerts-*
- 4 visualizaciones: barras por severidad (rule.level), tabla Top 10 IPs (data.srcip), línea de alertas por hora (@timestamp), y pie chart por tipo de regla (rule.groups).
- Dashboard: "SOC - Monitor de Seguridad" (exportado en dashboard_soc.json).
- Monitor de alerta: soc-nivel-critico, se activa cuando el conteo de eventos con rule.level >= 10 supera 5 en una ventana de 5 minutos.

---

## 5. Repositorio

https://github.com/AlexCoilaJrt/examen-practico-coila
