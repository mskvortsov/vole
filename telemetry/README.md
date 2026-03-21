# Telemetry Monitoring

1. Configure the device via the UART shell to send telemetry data
```
uart$ telemetry start 192.168.1.100
sending telemetry to udp 192.168.1.100:58761
```
2. Start containers
```
cd telemetry
docker compose up --detach
```
3. Open http://localhost:3000, default credentials are admin/admin, look for a Telemetry dashboard.

## Teardown

To shut down the containers and remove data volumes, run:
```
cd telemetry
docker compose down --volumes
```

To stop sending telemetry:
```
uart$ telemetry stop
stopped sending
```
