# src/idsec/collectors

| File | What it does |
|---|---|
| `__init__.py` | Package marker |
| `http.py` | Read-only HTTPS transport: allows GET (and POST to Azure Resource Graph only), follows paging, retries on throttling |
| `offline.py` | Validates a directory of exported files and copies it to the scan location |
| `live.py` | Collects from Microsoft Graph, Azure Resource Graph, Key Vault (metadata) and Foundry with `DefaultAzureCredential`. Written and tested against a fake cloud; never run against a tenant from this repository |
