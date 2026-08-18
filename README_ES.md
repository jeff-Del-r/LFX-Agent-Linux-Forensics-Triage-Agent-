cat << 'EOF' > README_ES.md
[🇬🇧 Read in English](README.md)

# LFX-Agent (Agente de Triage y Forensia en Linux)

**LFX-Agent** es una herramienta de línea de comandos (CLI) ligera y modular escrita en Python, diseñada para la respuesta rápida a incidentes y análisis forense digital en entornos Linux. Automatiza el triage de memoria volátil, detecta anomalías de ejecución a través de `/proc`, audita vectores de persistencia comunes y verifica la integridad de binarios del sistema, todo utilizando dependencias externas nulas o mínimas.

---

## Características Principales

* **Inspección de Proceso y Memoria Volátil (`memory_proc`):**
  * Detecta ejecuciones sigilosas a través de binarios desvinculados (`/proc/<PID>/exe` marcados como `deleted`).
  * Inspecciona descriptores de archivos (`/proc/<PID>/fd`) buscando sockets ocultos, tuberías o cargas maliciosas eliminadas en `/tmp` y `/dev/shm`.
  * Audita variables de entorno de procesos (`/proc/<PID>/environ`) para detectar inyección maliciosa de bibliotecas dinámicas (`LD_PRELOAD`).

* **Auditoría de Vectores de Persistencia (`persistence`):**
  * Audita tareas de CRON del sistema y de usuarios (`/etc/crontab`, `/var/spool/cron/crontabs/`, `/etc/cron.*`).
  * Escanea temporizadores activos de `systemd` y servicios personalizados de usuario.
  * Verifica inyecciones de claves no autorizadas en `~/.ssh/authorized_keys` en todas las cuentas del sistema.
  * Inspecciona archivos de inicio de la shell (`.bashrc`, `.profile`) y archivos globales de precalculado (`/etc/ld.so.preload`).

* **Correlación de Red y Sockets (`network`):**
  * Correlaciona conexiones de red TCP/UDP activas directamente con sus IDs de Proceso (PIDs) de origen.
  * Identifica interfaces de red operando en modo promiscuo (`PROMISC`).

* **Verificación de Integridad de Binarios (`integrity`):**
  * Calcula hashes SHA-256 de binarios críticos (`/bin/bash`, `/bin/ls`, `/bin/ps`, `/bin/ss`) para detectar modificaciones por rootkits.

* **Reportes Estructurados:**
  * Muestra registros claros en consola durante la ejecución.
  * Exporta reportes en formato JSON estructurado (`--json`) diseñados para ingesta directa en SIEMs (Wazuh, Elastic, Splunk).

---

## Cobertura de MITRE ATT&CK

| ID de Técnica | Nombre de la Técnica | Módulo LFX-Agent | Activador de Detección |
| :--- | :--- | :--- | :--- |
| **T1070.004** | Indicator Removal: File Deletion | `memory_proc` | Proceso ejecutándose desde un binario desvinculado (puntero `(deleted)`). |
| **T1574.006** | Hijack Execution Flow: LD_PRELOAD | `memory_proc` / `persistence` | `LD_PRELOAD` detectado en el entorno del proceso o en `/etc/ld.so.preload`. |
| **T1053.003** | Scheduled Task/Job: Cron | `persistence` | Entradas no estándar o recién agregadas en crontabs de usuario/sistema. |
| **T1543.002** | Create/Modify System Process: Systemd | `persistence` | Archivos de unidad o timers de `systemd` sospechosos. |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | `persistence` | Claves públicas no reconocidas agregadas a `authorized_keys`. |

---

## Estructura del Proyecto

```text
lfx-agent/
├── docs/
│   ├── architecture.png    # Flujo de arquitectura de alto nivel
│   └── mitre_mapping.md    # Alineación detallada con MITRE ATT&CK
├── lfx_agent/              # Paquete principal de la aplicación
│   ├── __init__.py
│   ├── cli.py              # Punto de entrada CLI y parseo de argumentos
│   ├── core/
│   │   ├── collector.py    # Orquestador de recolección
│   │   └── reporter.py     # Generadores de salida JSON y Consola
│   └── modules/
│       ├── memory_proc.py  # Inspector del sistema de archivos /proc
│       ├── network.py      # Recolector de artefactos de red y sockets
│       ├── persistence.py  # Auditor de Cron, systemd y SSH
│       └── integrity.py    # Generador de hashes SHA-256 de binarios
├── tests/                  # Suite de pruebas unitarias
├── LICENSE                 # Licencia MIT
├── README.md               # Documentación en Inglés
├── README_ES.md            # Documentación en Español
└── requirements.txt        # Dependencias opcionales (ej. rich, psutil)
