# 🛡️ ESCepcion

**Active Directory Certificate Services Auditor**

ESCepcion es una herramienta de código abierto (Open Source) para la auditoría y evaluación de vulnerabilidades en infraestructuras de **Active Directory Certificate Services (AD CS)**. Está diseñada para automatizar la detección de rutas de escalamiento de privilegios (ESC) con un enfoque estricto en la reducción de falsos positivos en entornos corporativos e híbridos.

A diferencia de otras herramientas, **ESCepcion no explota, modifica ni escribe ningún objeto en Active Directory**. Todas sus operaciones se basan exclusivamente en consultas de solo lectura a través de LDAP y lecturas opcionales de registro mediante MS-RRP (con el uso de `--deep-scan`).

---

## 🆚 ESCepcion vs. Certipy / Certify

En la comunidad existen excelentes herramientas referentes como **Certipy** y **Certify**, cuyo enfoque principal está orientado a las operaciones de Red Team y la **explotación activa** (solicitar certificados, emitirlos, forzar autenticaciones, etc.).

**ESCepcion no busca reemplazarlas, sino complementarlas desde la perspectiva defensiva:**
Mientras que Certipy/Certify son tu arsenal para *explotar* y demostrar el impacto técnico, **ESCepcion** se enfoca exclusivamente en la **auditoría pasiva y la validación de falsos positivos**. ESCepcion cruza datos de configuraciones LDAP, permisos en ACLs y validaciones de Registro de forma automatizada para generar reportes priorizados listos para su remediación.

---

## 🎯 Características Principales

*   **Detección Exhaustiva:** Cobertura de las vulnerabilidades más críticas (ESC1 - ESC16, CVE-2022-26923, CVE-2024-49019, etc.).
*   **Shadow Credentials (CBA):** Detección robusta de delegaciones inseguras en `msDS-KeyCredentialLink`, diferenciando riesgos reales de configuraciones legítimas (Windows Hello for Business, FIDO2).
*   **Anti-Falso Positivo:** Estados determinísticos. Todos los hallazgos se categorizan estrictamente en `EXPLOITABLE`, `NEAR_MISS`, `POTENTIAL`, `NOT_SCANNED` o `SAFE`, evitando la ambigüedad.
*   **Cadenas de Ataque (Combo Chains):** Identificación automática de vectores compuestos (DDCC) donde se combinan múltiples vulnerabilidades para comprometer el dominio.

---

## 🧠 Modelo de Riesgo (DDCC y L1–L5)

ESCepcion utiliza un modelo de riesgo propietario que va más allá de las clásicas puntuaciones de severidad:

*   **L1–L5:** Mapea cada hallazgo hacia la *ganancia real* del atacante (por ejemplo: suplantación privilegiada, minting de certificados), no solo por el tipo de vulnerabilidad técnica.
*   **DDCC (Dynamic Domain Compromise Chains):** Determina si los hallazgos encadenados forman una ruta viable hacia el compromiso total del dominio desde una cuenta de usuario estándar.

Puedes leer la documentación completa de nuestro modelo de riesgos en:
🔗 **[hackwarts12.github.io/ESCepcion/risk-model](https://hackwarts12.github.io/ESCepcion/risk-model)**

---

## ⚙️ Requisitos

*   Python 3.8+
*   Dependencias de Python listadas en `requirements.txt` (incluye librerías como `impacket`, `ldap3`, entre otras).

---

## 🚀 Instalación

Clona el repositorio e instala las dependencias de Python necesarias:

```bash
git clone https://github.com/TU-USUARIO/ESCepcion.git
cd ESCepcion
pip install -r requirements.txt
```

*(Opcional) Si existe un entorno de PowerShell específico, puedes ejecutar `install.ps1`.*

---

## 💻 Uso

Para ejecutar un escaneo básico autenticado contra un Controlador de Dominio:

```bash
python main.py -d midominio.local -dc-ip 192.168.1.100 -u usuario -p 'contraseña'
```

### Escaneo Profundo (Recomendado)
Agrega el parámetro `--deep-scan` para ejecutar verificaciones extra vía MS-RRP (Registro Remoto) y obtener un nivel de confianza más alto en la cobertura de ESCs específicos:

```bash
python main.py -d midominio.local -dc-ip 192.168.1.100 -u usuario -p 'contraseña' --deep-scan
```

### Otros Métodos de Autenticación
Autenticación utilizando el hash NTLM (Pass-the-Hash):
```bash
python main.py -d midominio.local -dc-ip 192.168.1.100 -u usuario -H 'LMHASH:NTHASH'
```

---

## 📊 Reportes (Output)

ESCepcion genera dos archivos tras cada escaneo:

1. **Dashboard HTML:** Un reporte interactivo que incluye:
   *   Puntuación de postura de seguridad (0–100).
   *   Visualización del Attack Chain y correlación de Combo Chains.
   *   Playbooks de remediación individuales por cada hallazgo con los comandos exactos para mitigar.
   *   Mapa de cobertura que muestra qué ESCs fueron evaluados y cuáles requieren un `--deep-scan`.

2. **Archivo JSON:** Una salida estructurada ideal para:
   *   Integración directa con herramientas SIEM.
   *   Seguimiento de remediación basado en el tracking de *diffs* históricos.
   *   Datos del PKI compatibles con grafos de BloodHound.

---

## 📁 Estructura del Proyecto

```text
ESCepcion/
├── main.py                # CLI principal de la herramienta
├── auth/                  # Módulos de conexión (LDAP, RPC, etc.)
├── modules/               # Módulos de chequeo (ESC1-16, Shadow Credentials, etc.)
├── utils/                 # Utilidades (Generador de reportes, Parseo de ACLs)
├── output/                # Directorio donde se generan los reportes JSON/HTML
│
# Archivos de Frontend (Landing Page / Documentación)
├── index.html             # Página principal Web
├── styles.css             # Estilos corporativos de la web
└── risk-model.html        # Documentación interactiva del modelo de riesgos
```

---

## 🎓 Créditos de Investigación

La lógica deductiva y de detección de ESCepcion está fuertemente construida sobre el excepcional trabajo de investigación de la comunidad de ciberseguridad:

*   **Will Schroeder & Lee Christensen (SpecterOps)** — *Certified Pre-Owned* (2021), investigación fundacional sobre vectores ESC1–ESC8.
*   **Oliver Lyak** — Creador de Certipy, investigación en vectores ESC9, ESC10 y ESC16.
*   **Jonas Bülow Knudsen** — Investigación sobre ESC13 y ESC14 (2024).
*   **Justin Bollinger (TrustedSec)** — Investigación sobre ESC15, EKUwu y CVE-2024-49019 (2024).

---

## 📜 Legal y Licencia

**Solo para pruebas de seguridad autorizadas.**
El uso de ESCepcion debe realizarse única y exclusivamente sobre infraestructuras en las que se tenga autorización explícita y por escrito para auditar. 

El proyecto se distribuye bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para más detalles.
