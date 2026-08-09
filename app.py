import hashlib
import math
import re
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from weasyprint import HTML
import streamlit as st

# ==========================================
# CONFIGURACIÓN DE LA PÁGINA Y TEMA SOC
# ==========================================
st.set_page_config(
    page_title="SentinelBox | Malware Analysis Sandbox",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilo personalizado SOC / CyberDark
CUSTOM_CSS = """
<style>
    /* Fondo general estilo SOC */
    .stApp {
        background-color: #0b0f19;
        color: #c9d1d9;
    }

    /* Encabezados y títulos */
    h1, h2, h3 {
        color: #58a6ff !important;
        font-family: 'Courier New', Courier, monospace;
    }

    /* Tarjetas de métricas */
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem !important;
        font-weight: bold;
        font-family: 'Courier New', Courier, monospace;
    }

    /* Paneles de datos */
    .cyber-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }

    /* Insignias de riesgo */
    .badge-critical {
        background-color: #8b0000;
        color: #ff7b72;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        border: 1px solid #f85149;
    }
    .badge-high {
        background-color: #5c2b00;
        color: #ffa657;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        border: 1px solid #d29922;
    }
    .badge-info {
        background-color: #0d3868;
        color: #58a6ff;
        padding: 4px 10px;
        border-radius: 4px;
        border: 1px solid #1f6beb;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ==========================================
# FUNCIONES DE ANÁLISIS ESTÁTICO REAL
# ==========================================
def calculate_hashes(file_bytes):
    """Calcula MD5, SHA1 y SHA256 del contenido del archivo."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }


def calculate_entropy(file_bytes):
    """Calcula la entropía de Shannon (0.0 a 8.0).
    Entropía > 7.0 suele indicar empaquetamiento o encriptación."""
    if not file_bytes:
        return 0.0
    entropy = 0.0
    byte_counts = [0] * 256
    for b in file_bytes:
        byte_counts[b] += 1
    total_bytes = len(file_bytes)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / total_bytes
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings_and_iocs(file_bytes):
    """Extrae artefactos y patrones IOC (IPs, URLs, Dominios) del archivo binary."""
    # Convertir bytes a texto imprimible ASCII/UTF-8
    text = "".join([chr(b) if 32 <= b <= 126 else "\n" for b in file_bytes])

    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b"

    ips = list(set(re.findall(ip_pattern, text)))
    urls = list(set(re.findall(url_pattern, text)))
    domains = list(set(re.findall(domain_pattern, text)))

    # Filtrar falsos positivos de dominios comunes en strings del SO
    domains = [d for d in domains if not d.endswith(('.dll', '.sys', '.exe', '.manifest'))][:10]

    return {
        "ips": ips[:10],
        "urls": urls[:10],
        "domains": domains
    }


def verify_digital_signature(filename):
    """Simulación de verificación de firma digital de PE."""
    if filename.endswith(".exe") or filename.endswith(".dll"):
        return {
            "signed": False,
            "status": "UNSIGNED / INVALID_SIGNATURE",
            "issuer": "N/A",
            "subject": "N/A"
        }
    return {
        "signed": False,
        "status": "N/A (No ejecutable estándar PE)",
        "issuer": "N/A",
        "subject": "N/A"
    }


# ==========================================
# MOTOR DE SIMULACIÓN DE ANÁLISIS DINÁMICO
# ==========================================
def generate_dynamic_sandbox_report(file_name, file_size, entropy):
    """Genera datos simulados pero coherentes de sandbox dinámico."""

    # Calcular nivel de riesgo según la entropía y extensión
    base_score = 40
    if entropy > 6.8:
        base_score += 35
    if file_name.endswith(('.exe', '.vbs', '.bat', '.ps1', '.dll', '.scr')):
        base_score += 15
    risk_score = min(base_score, 98)

    verdict = "CRÍTICO (Malware Confirmado)" if risk_score >= 80 else "SOSPECHOSO" if risk_score >= 50 else "BENIGNO"

    mitre_attack = [
        {"tactic": "Execution", "id": "T1059.001", "name": "PowerShell Scripting", "confidence": "Alta"},
        {"tactic": "Defense Evasion", "id": "T1027.002", "name": "Software Packing / High Entropy",
         "confidence": "Crítica"},
        {"tactic": "Persistence", "id": "T1547.001", "name": "Registry Run Keys / Startup Folder",
         "confidence": "Alta"},
        {"tactic": "Command & Control", "id": "T1071.001", "name": "Web Protocols (HTTP/HTTPS Exfiltration)",
         "confidence": "Media"},
        {"tactic": "Discovery", "id": "T1082", "name": "System Information Discovery", "confidence": "Media"}
    ]

    processes = [
        {"pid": 4128, "process": file_name, "path": f"C:\\Users\\Victim\\AppData\\Local\\Temp\\{file_name}",
         "action": "Iniciado (Padre)"},
        {"pid": 5892, "process": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe",
         "action": "Inyección / Invocación"},
        {"pid": 6012, "process": "powershell.exe",
         "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "action": "Ejecución de payload encoded"}
    ]

    registry = [
        {"hive": "HKCU", "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "UpdaterAgent",
         "data": f"C:\\Users\\Victim\\AppData\\Local\\Temp\\{file_name}"},
        {"hive": "HKLM", "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "value": "DisableAntiSpyware",
         "data": "0x00000001"}
    ]

    filesystem = [
        {"op": "CREAR_ARCHIVO", "path": "C:\\Users\\Victim\\AppData\\Roaming\\Microsoft\\Vault\\keys.dat",
         "size": "14 KB"},
        {"op": "MODIFICAR", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "size": "2 KB"},
        {"op": "ELIMINAR", "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\shadow_copy_backup.tmp", "size": "0 KB"}
    ]

    network_dns = [
        {"query": "c2-command-node.darknet-dns.org", "type": "A", "resolved_ip": "185.220.101.5", "status": "NOERROR"},
        {"query": "api.telegram.org", "type": "A", "resolved_ip": "149.154.167.220", "status": "NOERROR"},
        {"query": "exfil-server-drop.xyz", "type": "A", "resolved_ip": "91.215.102.14", "status": "NXDOMAIN"}
    ]

    yara_matches = [
        {"rule": "SUSP_PE_High_Entropy_Packed", "namespace": "malware_packers",
         "tags": ["packed", "UPX", "Obfuscated"]},
        {"rule": "INDICATOR_TOOL_PS_EncodedCommand", "namespace": "execution_evasion",
         "tags": ["PowerShell", "Base64"]},
        {"rule": "MALWARE_Win_AgentTesla_Behavior", "namespace": "stealer", "tags": ["InfoStealer", "Keylogger"]}
    ]

    sigma_rules = [
        {"title": "PowerShell Encoded Command Execution", "level": "High", "id": "proc_creation_win_powershell_base64"},
        {"title": "Persistence via Windows Run Registry Key", "level": "Medium",
         "id": "registry_event_run_key_persistence"},
        {"title": "Windows Defender Tampering via Registry", "level": "Critical", "id": "win_defender_disabled"}
    ]

    timeline = [
        {"time": "00:00:00", "event": "Ejecución del binario primario en entorno GUI aislado.", "severity": "Info"},
        {"time": "00:00:03", "event": "Desempaquetado en memoria y desempaquetamiento de recursos PE.",
         "severity": "Medio"},
        {"time": "00:00:07", "event": "Creación de proceso subyacente powershell.exe con flags ocultas (-W Hidden).",
         "severity": "Alto"},
        {"time": "00:00:12", "event": "Modificación de claves de registro para persistencia tras reinicio.",
         "severity": "Crítico"},
        {"time": "00:00:18", "event": "Intento de conexión saliente HTTP POST a C2 server (185.220.101.5).",
         "severity": "Crítico"}
    ]

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "mitre": mitre_attack,
        "processes": processes,
        "registry": registry,
        "filesystem": filesystem,
        "dns": network_dns,
        "yara": yara_matches,
        "sigma": sigma_rules,
        "timeline": timeline
    }

# se añade un botón para descargar reporte
def generate_pdf_report(filename, size_str, hashes, entropy, report, iocs, os_target):
    """Genera un reporte PDF con estilo profesional SOC utilizando WeasyPrint."""

    # Construcción de las filas de la tabla MITRE
    mitre_rows = "".join([
        f"<tr><td><b>{m['tactic']}</b></td><td><code>{m['id']}</code></td><td>{m['name']}</td><td><span style='color:#d29922;'>{m['confidence']}</span></td></tr>"
        for m in report['mitre']
    ])

    # Construcción de las filas de la línea de tiempo
    timeline_rows = "".join([
        f"<tr><td style='white-space:nowrap;'><b>{t['time']}</b></td><td>{t['event']}</td><td><b>{t['severity']}</b></td></tr>"
        for t in report['timeline']
    ])

    ioc_ips = ", ".join(list(set(iocs['ips'] + ["185.220.101.5", "149.154.167.220"])))
    ioc_doms = ", ".join(list(set(iocs['domains'] + ["c2-command-node.darknet-dns.org", "exfil-server-drop.xyz"])))

    # Plantilla HTML con estilos inline orientados a impresión PDF
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            @page {{
                size: A4;
                margin: 15mm 12mm;
                background-color: #0b0f19;
            }}
            *, *::before, *::after {{ box-sizing: border-box; }}
            body {{
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                color: #c9d1d9;
                background-color: #0b0f19;
                margin: 0;
                padding: 0;
                font-size: 10pt;
            }}
            .header {{
                background-color: #161b22;
                border-bottom: 2px solid #30363d;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 6px;
            }}
            .header h1 {{
                color: #58a6ff;
                margin: 0 0 5px 0;
                font-size: 18pt;
                font-family: monospace;
            }}
            .header p {{
                margin: 0;
                color: #8b949e;
                font-size: 9pt;
            }}
            .section-title {{
                color: #58a6ff;
                border-bottom: 1px solid #30363d;
                padding-bottom: 4px;
                margin-top: 20px;
                margin-bottom: 10px;
                font-size: 12pt;
                font-family: monospace;
            }}
            .badge-critical {{
                background-color: #8b0000;
                color: #ff7b72;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
            }}
            .box {{
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 12px;
                margin-bottom: 12px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 8px;
                font-size: 9pt;
            }}
            th, td {{
                border: 1px solid #30363d;
                padding: 6px 8px;
                text-align: left;
            }}
            th {{
                background-color: #21262d;
                color: #58a6ff;
            }}
            code {{
                font-family: monospace;
                background-color: #21262d;
                padding: 2px 4px;
                border-radius: 3px;
                color: #79c0ff;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ SENTINELBOX MALWARE ANALYSIS REPORT</h1>
            <p>Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Entorno VM: {os_target}</p>
        </div>

        <div class="box">
            <h3 style="margin-top:0; color:#ffffff;">Resumen de la Muestra</h3>
            <table style="border:none;">
                <tr style="border:none;">
                    <td style="border:none; width:50%;"><b>Nombre:</b> {filename}</td>
                    <td style="border:none;"><b>Nivel de Riesgo:</b> <span class="badge-critical">{report['risk_score']} / 100 ({report['verdict']})</span></td>
                </tr>
                <tr style="border:none;">
                    <td style="border:none;"><b>Tamaño:</b> {size_str}</td>
                    <td style="border:none;"><b>Entropía:</b> {entropy} / 8.0</td>
                </tr>
            </table>
        </div>

        <div class="section-title">🔑 HASHS DE IDENTIFICACIÓN</div>
        <div class="box">
            <p style="margin:2px 0;"><b>MD5:</b> <code>{hashes['md5']}</code></p>
            <p style="margin:2px 0;"><b>SHA1:</b> <code>{hashes['sha1']}</code></p>
            <p style="margin:2px 0;"><b>SHA256:</b> <code>{hashes['sha256']}</code></p>
        </div>

        <div class="section-title">🎯 MATRIZ MITRE ATT&CK</div>
        <table>
            <thead>
                <tr><th>Táctica</th><th>Técnica ID</th><th>Nombre</th><th>Confianza</th></tr>
            </thead>
            <tbody>
                {mitre_rows}
            </tbody>
        </table>

        <div class="section-title">🌐 INDICADORES DE COMPROMISO (IOCs)</div>
        <div class="box">
            <p><b>Direcciones IP Detectadas:</b> <code>{ioc_ips}</code></p>
            <p><b>Dominios C2 Identificados:</b> <code>{ioc_doms}</code></p>
        </div>

        <div class="section-title">⏳ LÍNEA DE TIEMPO DE EJECUCIÓN</div>
        <table>
            <thead>
                <tr><th>Tiempo</th><th>Evento Simulado / Detectado</th><th>Severidad</th></tr>
            </thead>
            <tbody>
                {timeline_rows}
            </tbody>
        </table>
    </body>
    </html>
    """

    # Convierte el HTML a bytes PDF en memoria
    return HTML(string=html_content).write_pdf()
# fin de botón
# ==========================================
# INTERFAZ PRINCIPAL Y BARRA LATERAL
# ==========================================
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=70)
st.sidebar.title("SentinelBox Sandbox")
st.sidebar.caption("Plataforma de Análisis Dinámico & Estático v2.4")

st.sidebar.markdown("---")
st.sidebar.subheader("⚙️ Configuración del Sandbox")
os_target = st.sidebar.selectbox("Entorno Virtualizado (VM):",
                                 ["Windows 10 Pro x64 (22H2)", "Windows 11 Enterprise", "Ubuntu Linux 22.04 LTS"])
analysis_timeout = st.sidebar.slider("Tiempo de Ejecución (segundos):", 30, 300, 60)
enable_network = st.sidebar.checkbox("Simular Red (INetSim / Tor Sinkhole)", value=True)

st.sidebar.markdown("---")
st.sidebar.info(
    "💡 **Tip:** Arrastra archivos ejecutable (.exe, .dll), scripts (.vbs, .ps1) o documentos con macros (.docm).")

# Título Principal
st.title("🛡️ SentinelBox | Malware Analysis Sandbox")
st.caption("Entorno seguro para la inspección profunda de amenazas, extracción de IOCs y mapeo MITRE ATT&CK.")

# Carga de Archivos (Drag & Drop)
uploaded_file = st.file_uploader("📥 Arrastra y suelta un archivo sospechoso para iniciar el análisis", type=None)

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()

    # Formatear tamaño automáticamente en MB o KB
    bytes_len = len(file_bytes)
    if bytes_len >= 1024 * 1024:
        size_str = f"{round(bytes_len / (1024 * 1024), 2)} MB"
    else:
        size_str = f"{round(bytes_len / 1024, 2)} KB"

    # 1. Ejecutar Análisis Estático Real
    hashes = calculate_hashes(file_bytes)
    entropy = calculate_entropy(file_bytes)
    extracted_iocs = extract_strings_and_iocs(file_bytes)
    sig_info = verify_digital_signature(uploaded_file.name)

    # 2. Generar Reporte de Análisis Dinámico
    report = generate_dynamic_sandbox_report(uploaded_file.name, size_str, entropy)

    st.markdown("---")

    # BANNER RESUMEN SUPERIOR
    col_v1, col_v2, col_v3, col_v4 = st.columns([1.5, 1, 1, 1])
    # Generar el archivo PDF en memoria
    pdf_bytes = generate_pdf_report(
        filename=uploaded_file.name,
        size_str=size_str,
        hashes=hashes,
        entropy=entropy,
        report=report,
        iocs=extracted_iocs,
        os_target=os_target
    )

    # Mostrar botón destacado para la descarga
    st.download_button(
        label="📄 Descargar Reporte Ejecutivo en PDF",
        data=pdf_bytes,
        file_name=f"Reporte_SentinelBox_{uploaded_file.name}.pdf",
        mime="application/pdf",
        type="primary"
    )
    with col_v1:
        st.markdown(f"### Archivo: `{uploaded_file.name}`")
        if report['verdict'] == "CRÍTICO (Malware Confirmado)":
            st.markdown(f"**Veredicto:** <span class='badge-critical'>{report['verdict']}</span>",
                        unsafe_allow_html=True)
        else:
            st.markdown(f"**Veredicto:** <span class='badge-high'>{report['verdict']}</span>", unsafe_allow_html=True)

    with col_v2:
        st.metric(label="Puntuación de Riesgo", value=f"{report['risk_score']} / 100", delta="Riesgo Elevado",
                  delta_color="inverse")

    with col_v3:
        st.metric(label="Entropía del Archivo", value=f"{entropy}",
                  delta="Empaquetado/Cifrado" if entropy > 7.0 else "Normal")

    with col_v4:
        st.metric(label="Tamaño del Archivo", value=size_str)

    st.markdown("<br>", unsafe_allow_html=True)

    # NAVEGACIÓN POR PESTAÑAS
    tab_summary, tab_static, tab_mitre, tab_dynamic, tab_network, tab_rules, tab_timeline = st.tabs([
        "📋 Resumen Ejecutivo",
        "🔍 Análisis Estático & Hashes",
        "🎯 Matriz MITRE ATT&CK",
        "⚡ Comportamiento Dinámico",
        "🌐 Red & IOCs Extracción",
        "🛡️ Reglas YARA & Sigma",
        "⏳ Línea de Tiempo"
    ])

    # ==========================================
    # PESTAÑA 1: RESUMEN EJECUTIVO
    # ==========================================
    with tab_summary:
        col_s1, col_s2 = st.columns([2, 1])

        with col_s1:
            st.subheader("📝 Resumen para la Gerencia de Ciberseguridad")
            st.markdown(f"""
            Durante el análisis automatizado en el entorno virtualizado **{os_target}**, la muestra identificada como **`{uploaded_file.name}`** demostró un comportamiento altamente malicioso. 

            Se detectaron técnicas de **evasión de defensas** mediante empaquetamiento con alta entropía ($H = {entropy}$), seguidas de ejecución de comandos PowerShell codificados en Base64. El artefacto estableció persistencia en el sistema mediante modificaciones en el registro de Windows y realizó intentos de comunicación saliente hacia direcciones IP de comando y control (C2).
            """)

            st.subheader("💡 Recomendaciones del Analista SOC")
            st.error(
                "1. **Aislamiento Inmediato:** Bloquear la dirección IP `185.220.101.5` y el dominio `c2-command-node.darknet-dns.org` en el Firewall de borde/EDR.")
            st.warning(
                "2. **Remediación en Hosts:** Eliminar el valor de registro en `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterAgent` en los endpoints afectados.")
            st.info(
                "3. **Cacería de Amenazas (Threat Hunting):** Ejecutar un barrido de red en la infraestructura buscando coincidencias con el SHA256.")

        with col_s2:
            st.subheader("📊 Indicador de Amenaza")
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=report['risk_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Nivel de Amenaza"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#ff4b4b"},
                    'steps': [
                        {'range': [0, 40], 'color': "#1f6beb"},
                        {'range': [40, 75], 'color': "#d29922"},
                        {'range': [75, 100], 'color': "#8b0000"}
                    ]
                }
            ))
            fig_gauge.update_layout(paper_bgcolor='#0b0f19', font={'color': "white"}, height=280)
            st.plotly_chart(fig_gauge, use_container_width=True)

    # ==========================================
    # PESTAÑA 2: ANÁLISIS ESTÁTICO & HASHES
    # ==========================================
    with tab_static:
        st.subheader("🔑 Identificación y Hashes")
        st.code(f"""
MD5:    {hashes['md5']}
SHA1:   {hashes['sha1']}
SHA256: {hashes['sha256']}
        """, language="text")

        col_st1, col_st2 = st.columns(2)

        with col_st1:
            st.subheader("📦 Propiedades del Archivo")
            df_props = pd.DataFrame([
                {"Propiedad": "Nombre", "Valor": uploaded_file.name},
                {"Propiedad": "Tipo de Archivo",
                 "Valor": uploaded_file.type if uploaded_file.type else "application/octet-stream"},
                {"Propiedad": "Firma Digital", "Valor": sig_info['status']},
                {"Propiedad": "Arquitectura Evaluada", "Valor": "x86 / x64 PE Executable"}
            ])
            st.table(df_props)

        with col_st2:
            st.subheader("📈 Análisis de Entropía")
            st.write(f"Entropía calculada: **{entropy} / 8.0**")

            # Gráfico visual de nivel de entropía
            fig_ent = px.bar(
                x=["Entropía Muestra", "Umbral Empaquetado"],
                y=[entropy, 7.0],
                labels={'x': 'Métrica', 'y': 'Valor de Entropía'},
                color_discrete_sequence=['#ff7b72', '#58a6ff']
            )
            fig_ent.update_layout(paper_bgcolor='#0b0f19', plot_bgcolor='#161b22', font={'color': "white"}, height=220)
            st.plotly_chart(fig_ent, use_container_width=True)

    # ==========================================
    # PESTAÑA 3: MATRIZ MITRE ATT&CK
    # ==========================================
    with tab_mitre:
        st.subheader("🎯 Tácticas y Técnicas Mapeadas")
        df_mitre = pd.DataFrame(report['mitre'])
        st.dataframe(df_mitre, use_container_width=True)

    # ==========================================
    # PESTAÑA 4: COMPORTAMIENTO DINÁMICO
    # ==========================================
    with tab_dynamic:
        st.subheader("🌳 Árbol de Procesos Sospechosos")
        df_proc = pd.DataFrame(report['processes'])
        st.dataframe(df_proc, use_container_width=True)

        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.subheader("🔑 Modificaciones en el Registro")
            st.dataframe(pd.DataFrame(report['registry']), use_container_width=True)

        with col_d2:
            st.subheader("📁 Cambios en el Sistema de Archivos")
            st.dataframe(pd.DataFrame(report['filesystem']), use_container_width=True)

    # ==========================================
    # PESTAÑA 5: RED Y IOCS EXTRAÍDOS
    # ==========================================
    with tab_network:
        st.subheader("🌐 Conexiones y Peticiones DNS")
        st.dataframe(pd.DataFrame(report['dns']), use_container_width=True)

        st.markdown("---")
        st.subheader("🔍 Indicadores de Compromiso (IOCs) Extraídos del Binario")

        col_ioc1, col_ioc2, col_ioc3 = st.columns(3)
        with col_ioc1:
            st.markdown("**Direcciones IP Detectadas:**")
            all_ips = list(set(extracted_iocs['ips'] + ["185.220.101.5", "149.154.167.220"]))
            for ip in all_ips:
                st.code(ip, language="text")

        with col_ioc2:
            st.markdown("**Dominios Identificados:**")
            all_domains = list(
                set(extracted_iocs['domains'] + ["c2-command-node.darknet-dns.org", "exfil-server-drop.xyz"]))
            for dom in all_domains:
                st.code(dom, language="text")

        with col_ioc3:
            st.markdown("**URLs Extraídas:**")
            all_urls = list(set(extracted_iocs['urls'] + ["http://185.220.101.5/gate.php"]))
            for url in all_urls:
                st.code(url, language="text")

    # ==========================================
    # PESTAÑA 6: REGLAS YARA & SIGMA
    # ==========================================
    with tab_rules:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            st.subheader("🧪 Coincidencias con Reglas YARA")
            for yara in report['yara']:
                with st.expander(f"Regla: {yara['rule']}", expanded=True):
                    st.write(f"**Namespace:** `{yara['namespace']}`")
                    st.write(f"**Etiquetas:** `{', '.join(yara['tags'])}`")

        with col_r2:
            st.subheader("🚨 Detecciones de Reglas Sigma")
            for sigma in report['sigma']:
                with st.expander(f"[{sigma['level'].upper()}] {sigma['title']}", expanded=True):
                    st.write(f"**ID de Regla:** `{sigma['id']}`")
                    st.write(f"**Nivel de Severidad:** `{sigma['level']}`")

    # ==========================================
    # PESTAÑA 7: LÍNEA DE TIEMPO DE COMPORTAMIENTO
    # ==========================================
    with tab_timeline:
        st.subheader("⏳ Cronología de Eventos durante la Ejecución")
        for item in report['timeline']:
            sev_color = "🔴" if item['severity'] in ["Crítico", "Alto"] else "🟡" if item['severity'] == "Medio" else "🔵"
            st.markdown(f"**`[{item['time']}]`** {sev_color} **{item['event']}** *(Severidad: {item['severity']})*")

else:
    # Estado inicial cuando no hay archivo subido
    st.info(
        "👆 Por favor, carga un archivo ejecutable, documento o script arriba para iniciar la secuencia de análisis.")

    # Vista previa estilo Dashboard
    st.markdown("### 📊 Estado de la Infraestructura de Análisis")
    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Nodos de Ejecución Sandbox", "4 Activos", "Online")
    col_m2.metric("Muestras Analizadas Hoy", "142", "+18%")
    col_m3.metric("Firma de Amenazas Activas", "v2026.08.08", "Actualizado")