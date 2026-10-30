# Native Isolated Juice Shop Lab

Juice Shop v17.2.0 is built from its official source on the SSD and bound to `127.0.0.1:3000`. Node.js 22.14.0 satisfies the source release's `18 - 22` engine requirement. Docker is optional and is not required for this native setup.

Start the SSD-native build and check it:

```bash
/Volumes/FYP-DEV/Projects/FYP/start_juice_shop.sh
curl --fail http://127.0.0.1:3000/
```

Register `http://127.0.0.1:3000` in the application with scope `allowlisted`, allowed tools `nmap,ffuf,gobuster,nikto`, and mock mode first. The backend rejects public targets by default.

The runner records its PID and log at `/Volumes/FYP-DEV/Runtime/juice-shop.pid` and `/Volumes/FYP-DEV/Logs/juice-shop.log`. Stop it with the SSD `stop_fyp.sh` script. Juice Shop resets its SQLite lab state at startup (`sequelize.sync({ force: true })`), so restarting the process resets the lab database.

Docker Compose remains an optional fallback, loopback-bound by [docker-compose.yml](docker-compose.yml):

```bash
docker compose up -d juice-shop
docker compose down
```

Do not use the lab against public systems. A benchmark scenario is provided at `backend/data/benchmark_scenarios.json`, but its vulnerability and attack-path lists are intentionally empty until verified by the operator. Do not treat illustrative or scanner-generated data as ground truth.
