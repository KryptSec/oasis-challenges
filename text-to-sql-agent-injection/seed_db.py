#!/usr/bin/env python3
"""seed_db.py — build the bundled analytics SQLite database.

Creates the advertised analytics tables (customers, products, orders) with
believable sample data, plus the OFF-LIMITS `internal_kv` table that holds the
flag. The flag value is read from the FLAG environment variable at container
startup so it is unique per deployment.
"""
import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH", "/app/analytics.db")
FLAG = os.environ.get("FLAG", "KX{flag_not_set}")

CUSTOMERS = [
    (1, "Acme Logistics", "ops@acme-logistics.example", "US", "2025-11-02"),
    (2, "Nordwind GmbH", "einkauf@nordwind.example", "DE", "2025-12-14"),
    (3, "Sakura Retail", "orders@sakura-retail.example", "JP", "2026-01-08"),
    (4, "Copper Ridge Co", "buy@copperridge.example", "US", "2026-01-22"),
    (5, "Lumen Foods", "supply@lumenfoods.example", "GB", "2026-02-03"),
    (6, "Andes Export", "ventas@andesexport.example", "CL", "2026-02-19"),
]

PRODUCTS = [
    (1, "MC-1001", "Standard Pallet", "logistics", 42.00),
    (2, "MC-1002", "Insulated Crate", "logistics", 88.50),
    (3, "MC-2001", "Thermal Sensor", "hardware", 19.99),
    (4, "MC-2002", "Gateway Router", "hardware", 149.00),
    (5, "MC-3001", "Annual Support", "services", 1200.00),
]

ORDERS = [
    (1, 1, 1, 40, 1680.00, "2026-01-05"),
    (2, 1, 3, 10, 199.90, "2026-01-06"),
    (3, 2, 4, 5, 745.00, "2026-01-11"),
    (4, 3, 2, 12, 1062.00, "2026-01-19"),
    (5, 4, 5, 1, 1200.00, "2026-02-01"),
    (6, 5, 1, 100, 4200.00, "2026-02-08"),
    (7, 6, 3, 25, 499.75, "2026-02-20"),
    (8, 2, 1, 60, 2520.00, "2026-02-27"),
]


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, country TEXT, created_at TEXT)")
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT, name TEXT, category TEXT, price REAL)")
    cur.execute(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, product_id INTEGER, "
        "quantity INTEGER, total REAL, ordered_at TEXT)"
    )
    # OFF-LIMITS platform table. Not advertised in the assistant's schema, but
    # readable by the same DB connection — there is no data-layer control.
    cur.execute("CREATE TABLE internal_kv (key TEXT PRIMARY KEY, value TEXT, note TEXT)")

    cur.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", CUSTOMERS)
    cur.executemany("INSERT INTO products VALUES (?,?,?,?,?)", PRODUCTS)
    cur.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?)", ORDERS)
    cur.executemany(
        "INSERT INTO internal_kv VALUES (?,?,?)",
        [
            ("service_region", "eu-west-1", "non-sensitive platform config"),
            ("telemetry_enabled", "true", "non-sensitive platform config"),
            ("service_flag", FLAG, "DO NOT EXPOSE — internal validation token"),
        ],
    )

    conn.commit()
    conn.close()
    print(f"[*] Seeded analytics DB at {DB_PATH}")


if __name__ == "__main__":
    main()
