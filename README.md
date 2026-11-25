# omniguard-analyzer-python

El analizador consume eventos desde Redis, detecta amenazas, persiste activos y
servicios en PostgreSQL, envía alertas al Core Java y notifica por Discord.

El worker de escaneo activo vive en `scan_worker.py`. Solo inicia por separado
cuando el endpoint interno está disponible y se ha configurado una allowlist
de IPs propias.

## Pruebas

Ejecuta las pruebas unitarias con:

```powershell
python -m unittest discover -v
```

Para validar el recorrido Redis -> servicio TCP de loopback -> callback HTTP sin
depender del backend Java, levanta un Redis local y configura
`SCAN_WORKER_TEST_REDIS_PORT` antes de ejecutar:

```powershell
$env:SCAN_WORKER_TEST_REDIS_PORT = "16379"
python -m unittest test_scan_worker_integration -v
```
