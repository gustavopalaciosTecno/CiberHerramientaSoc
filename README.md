# 🛡️ SentinelBox | Malware Analysis Sandbox

**SentinelBox** es un sandbox dinámico y estático de análisis de malware construido con **Streamlit** y diseñado para entornos de **SOC (Security Operations Center)** y **Threat Intelligence**. Permite a analistas e investigadores inspeccionar archivos sospechosos, extraer Indicadores de Compromiso (IOCs), mapear comportamientos con la matriz **MITRE ATT&CK** y enriquecer la investigación en tiempo real con **VirusTotal**.

---

## ✨ Características Principales

* 🔑 **Inteligencia Global con VirusTotal:** Integración directa con la API v3 de VirusTotal mediante gestión segura de claves (*Streamlit Secrets* o entrada manual).
* 🧪 **Análisis Estático Real:** 
  * Cálculo instantáneo de hashes criptográficos (`MD5`, `SHA-1`, `SHA-256`).
  * Análisis de **Entropía de Shannon** en tiempo real para detectar ofuscación, cifrado o empaquetado (e.g. UPX).
  * Extracción automática de cadenas, direcciones IP, dominios C2 y URLs.
* 🎯 **Matriz MITRE ATT&CK:** Mapeo automatizado de tácticas y técnicas detectadas durante el análisis.
* ⚡ **Simulación de Comportamiento Dinámico:**
  * Árbol de procesos ejecutados.
  * Modificaciones en el Registro de Windows y sistema de archivos.
  * Tráfico de red y peticiones DNS simuladas.
  * Reglas de detección **YARA** y **Sigma**.
* 📄 **Reportes Ejecutivos en PDF:** Exportación inmediata de informes listos para auditorías o incident response mediante **WeasyPrint**.
* 🎨 **Interfaz CyberDark / SOC:** Panel visual optimizado para entornos de operaciones con tema oscuro personalizado e indicadores visuales de amenaza.

---

## 🛠️ Requisitos Previos

Asegúrate de contar con Python 3.10+ y las dependencias del sistema requeridas para la compilación de reportes PDF (WeasyPrint).

### Dependencias de Python
```bash
pip install streamlit pandas plotly requests weasyprint