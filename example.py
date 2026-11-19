import getpass
import os

from hfsql import connect


password = os.getenv("HFSQL_PASSWORD")
if password is None:
    password = getpass.getpass("HFSQL password: ")

db = connect(
    host=os.getenv("HFSQL_HOST", "localhost"),
    port=int(os.getenv("HFSQL_PORT", "4900")),
    database=os.environ["HFSQL_DATABASE"],
    user=os.environ["HFSQL_USER"],
    password=password,
)

print("Database:", db.database)
print("Tables:", db.tables())
