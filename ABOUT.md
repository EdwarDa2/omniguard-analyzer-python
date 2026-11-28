# Acerca de omniguard-analyzer-python

## Descripción General

`omniguard-analyzer-python` es el motor de detección heurística de intrusiones en red (NIDS) y análisis de telemetría de la plataforma **OmniGuard SOC**. Su responsabilidad técnica consiste en consumir en tiempo real los flujos de eventos crudos publicados por los sensores en Redis Pub/Sub, ejecutar algoritmos de ventana deslizante para identificar patrones de ataque, persistir activos e incidentes en PostgreSQL y despachar alertas tempranas hacia plataformas externas (Discord y Telegram) y hacia el núcleo transaccional en Java.

Adicionalmente, incorpora un módulo de auditoría activa bajo demanda (`scan_worker.py`) sujeto a listas blancas de red (*allowlist*) para sondeos TCP no bloqueantes, extracción de banners y deducción de identificadores CPE.

## Contexto del Proyecto

* **Plataforma:** OmniGuard SOC (Security Operations Center Distribuido)
* **Capa Arquitectónica:** Capa Analítica e Inteligencia de Amenazas
* **Tecnologías Principales:** Python 3.11+, Redis Pub/Sub, PostgreSQL 16 (`psycopg3`), Discord Webhooks, Telegram Bot API
* **Licencia:** MIT License
* **Institución:** Universidad Politécnica de Chiapas — Ingeniería en Tecnologías de la Información e Innovación Digital
* **Autores:** Edwar Daniel Gonzalez Hernandez, Andres Eduardo Gonzalez Ruiz

---

## Metadatos para la sección "About" de GitHub

Copiar y pegar estos valores en el panel lateral derecho (icono de engranaje en **About**) del repositorio en GitHub:

* **Description:**
  `Motor NIDS de deteccion heuristica en tiempo real en Python para OmniGuard SOC. Analisis por ventana deslizante, consumo Redis Pub/Sub, persistencia PostgreSQL y alertas tempranas.`
* **Topics:**
  `cybersecurity`, `nids`, `blue-team`, `python`, `redis`, `postgresql`, `threat-detection`, `soc`, `omniguard`
