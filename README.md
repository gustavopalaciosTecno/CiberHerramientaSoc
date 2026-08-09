# 🛡️ SentinelBox | Malware Analysis & SOC Sandbox

**SentinelBox** es una plataforma interactiva de análisis estático de archivos e Indicadores de Compromiso (IOCs) diseñada para analistas de SOC (*Security Operations Center*) e investigadores de ciberseguridad. Ofrece una interfaz moderna en estilo *CyberDark* para examinar muestras sospechosas, analizar la entropía de los datos y generar reportes ejecutivos en PDF.

---

## 🚀 Características Principales

* **🔍 Análisis Estático de Archivos:** Cálculo automático de metadatos clave y firmas criptográficas (`MD5`, `SHA-1`, `SHA-256`).
* **📊 Evaluación de Entropía Criptográfica:** Visualizaciones interactivas con Plotly para detectar ofuscación, empaquetado (*packers*) o contenido cifrado.
* **⚠️ Extracción de IOCs & Veredicto:** Clasificación dinámica de nivel de amenaza (Limpio, Sospechoso, Crítico) e identificación de artefactos maliciosos.
* **📄 Generación de Reportes PDF:** Exportación de informes técnicos listos para auditoría mediante **WeasyPrint**.
* **🖥️ Interfaz SOC CyberDark:** Dashboard optimizado por pestañas con estética oscura de operaciones de seguridad.

---

## 🛠️ Tecnologías Utilizadas

* **Lenguaje:** Python 3.10+
* **Frontend / Dashboard:** [Streamlit](https://streamlit.io/)
* **Procesamiento de Datos & Gráficos:** Pandas, Plotly
* **Motor de Reportes PDF:** WeasyPrint (requiere bibliotecas nativas C / GTK)

---

## 📁 Estructura del Proyecto

```text
├── app.py              # Código principal de la aplicación Streamlit
├── requirements.txt    # Dependencias de Python (Streamlit, Pandas, Plotly, WeasyPrint)
├── packages.txt        # Dependencias nativas Linux para Streamlit Cloud (GTK/Pango)
├── .gitignore          # Archivos excluidos del control de versiones
└── README.md           # Documentación del proyecto