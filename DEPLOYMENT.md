# Despliegue web — OmniGuard Analyzer Python

Consulte el plan maestro en el repositorio central:

[WEB-DEPLOYMENT-PLAN.md](../WEB-DEPLOYMENT-PLAN.md)

## Rol

El analizador consume eventos desde Redis, persiste activos y servicios en PostgreSQL, envía alertas al Core Java y puede notificar por Discord.

## Variables

```text
REDIS_HOST
REDIS_PORT
REDIS_CHANNEL
POSTGRES_HOST
POSTGRES_PORT
POSTGRES_DB
POSTGRES_USER
POSTGRES_PASSWORD
CORE_API_URL
INTERNAL_API_TOKEN
DISCORD_WEBHOOK_URL
```

## Producción

No ejecutar con `--dry-run`. Debe consumir `network_events` y enviarse a Discord únicamente con una URL válida.

## Inicio

```powershell
docker compose up -d --build
```
