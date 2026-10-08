"""Collectors write raw Graph / ARM / Key Vault / Foundry / SaaS JSON in the layout that
`idsec.inventory.load` reads (see data/tenant/README.md).

* `offline`  copies and checks a directory of files (the synthetic tenant, or files exported elsewhere).
* `live`     reads a real tenant through Microsoft Graph, Azure Resource Graph, ARM, Key Vault and the
             Foundry project endpoint, with `DefaultAzureCredential` and a transport that refuses any
             write. Written and tested against a fake transport; never run against a tenant from this
             repository."""
