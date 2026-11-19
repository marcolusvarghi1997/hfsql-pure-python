![A Python bridge carrying read-only data from an HFSQL server to different applications](docs/hfsql-bridge.png)

# Pure Python HFSQL client

An experimental, read-only HFSQL Client/Server client written with the Python standard library. It connects directly to a server without ODBC, PC SOFT DLLs, native installers, or runtime dependencies.

The project turns a protocol implementation originally verified against one database into a reusable client: the host, database, username, and password are supplied by the caller, while table and column names are discovered from the server.

> [!IMPORTANT]
> This is an independent protocol implementation, not an official PC SOFT driver. It has been tested against a limited HFSQL v31 environment; other server releases and schema types still need real-world verification. Start with a dedicated read-only account and a non-production database.

## What it does

- Lists the tables visible to an HFSQL user.
- Reads up to 1,000 rows at a time as Python dictionaries.
- Supports an exact string/integer filter and numeric keyset pagination.
- Decodes common integers, text, booleans, date/time values, floats, currency, binary identifiers, and binary memos.
- Exposes no write, update, delete, or arbitrary-SQL API.

## Requirements

- Python 3.10 or newer.
- Network access to an HFSQL Client/Server endpoint (port `4900` by default).
- An HFSQL account with permission to read the target database.

## Install

Clone or download this repository, then install it locally:

```console
python -m pip install .
```

There are no runtime dependencies. You can also copy `hfsql.py` next to a small script and import it directly.

## Quick start

```python
from getpass import getpass

from hfsql import connect


db = connect(
    host="hfsql.example.net",
    port=4900,
    database="MY_DATABASE",
    user="report_reader",
    password=getpass("HFSQL password: "),
)

print(db.tables())

for row in db.rows("Products", limit=20):
    print(row)
```

Credentials and the database name have no built-in defaults. `host` defaults to `localhost`, `port` to `4900`, and the socket timeout to 10 seconds.

## Filtering and pagination

`rows()` deliberately accepts a small, safe query surface rather than arbitrary SQL:

```python
# Exact string or integer match.
product = db.rows("Products", limit=1, where=("ProductID", 42))

# Page ordered by a numeric key; use the previous page's last key as the cursor.
page = db.rows("Products", limit=1000, after=("ProductID", 1000))

# Filter and page together.
page = db.rows(
    "Products",
    limit=1000,
    where=("CategoryID", 7),
    after=("ProductID", 1000),
)
```

Table and column identifiers are checked locally and then resolved case-insensitively against the server schema. String literals are escaped by the driver. `limit` must be between 1 and 1,000.

For pagination, use a unique, non-NULL, stable numeric key. Pass `after` on the first page too, with a cursor below the table's minimum key, because a call without `after` has no guaranteed order. Reusing a non-unique value can skip rows that share the page boundary.

Binary memo values are returned as `bytes`, NULL memos as `None`, and HFSQL currency values as `Decimal`. Date/time values are ISO-formatted strings so they remain easy to serialize.

## Configuration example

[`example.py`](example.py) reads connection settings from environment variables, so secrets do not need to be written into source code:

```powershell
$env:HFSQL_HOST = "hfsql.example.net"
$env:HFSQL_DATABASE = "MY_DATABASE"
$env:HFSQL_USER = "report_reader"
python example.py
```

`HFSQL_PASSWORD` is optional; when it is absent the example prompts without echo. `HFSQL_PORT` defaults to `4900`.

## Errors and safety

Protocol, authentication, malformed-frame, and server errors raise `HFSQLDriverError`. Invalid local arguments raise `ValueError` before a query is sent.

The public API is read-only, but a read-only client can still expose sensitive data. Use a least-privilege account, protect credentials, and avoid untrusted networks: this experimental client does not add TLS around the HFSQL connection.

## Test

The unit tests use synthetic protocol frames and do not need a running server:

```console
python -B -m unittest -v test_hfsql.py
```

For a real compatibility check, run `example.py` against a disposable database and verify both `tables()` and representative `rows()` calls. A successful test on one HFSQL release does not prove compatibility with every release or column type.

## Current limits

- Read-only operations only.
- Maximum 1,000 rows per call; safe pagination requires a unique, non-NULL, stable numeric key.
- Exact equality filters accept strings and integers only.
- No TLS, connection pooling, async API, ORM adapter, or official vendor support.
- The wire protocol is undocumented and may change between HFSQL versions.

Those limits keep the implementation small and make its safety boundary visible. Add broader protocol support only with captures and tests from the HFSQL version that needs it.

## License

MIT. See [`LICENSE`](LICENSE). HFSQL and PC SOFT are trademarks of their respective owners; this project is not affiliated with or endorsed by PC SOFT.
