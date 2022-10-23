"""
Analyze CloudTrail JSON data.
"""

import datetime as dt
import logging
import os
import sys
import time
from sqlite3 import Connection, Cursor, connect
from types import SimpleNamespace as ns
from typing import Generator, List, Tuple

import ijson

FNDB = "cloudtrail.db"
FNJSON = "cloudtrail-2022-03.json"


def create_table(con: Connection, cur: Cursor, name: str, columns: List[str]) -> None:
    """
    Create a database table with the given name and columns.
    Args:
        con: The database connection
        cur: The database cursor
        name: The table name
        columns: The table columns
    """
    cur.execute("create table %s(%s)" % (name, ", ".join(columns)))
    con.commit()


def create_tables(con: Connection, cur: Cursor) -> None:
    """
    Create database tables.
    Args:
        con: The database connection
        cur: The database cursor
    """
    # Resources table:
    create_table(
        con=con,
        cur=cur,
        name="resources",
        columns=[
            "arn text primary key",
            "iam text",
            "created int",
            "deleted int",
        ],
    )
    # Accesses table:
    create_table(
        con=con,
        cur=cur,
        name="accesses",
        columns=[
            "arn text",
            "iam text",
            "ts int",
            "type text",
        ],
    )


def exist_between(fndb: str, t0: int, t1: int) -> None:
    """
    Find resources existing between the two times.
    Args:
        fndb: Database filename
        t0: Initial time (Unix timestamp)
        t1: Initial time (Unix timestamp)
    """
    con = connect(fndb)
    cur = con.cursor()
    for row in cur.execute("select * from resources").fetchall():
        arn, _, created, deleted = row
        if created >= t0 and (deleted == -1 or deleted <= t1):
            logging.info(
                "ARN %s created %s deleted %s existed between %s and %s",
                arn,
                tsfmt(created),
                tsfmt(deleted),
                tsfmt(t0),
                tsfmt(t1),
            )
    con.close()


def finite_resources(fndb: str) -> None:
    """
    Find resources created and deleted within the span of times covered by the
    raw JSON records.
    Args:
        fndb: Database filename
    """
    con = connect(fndb)
    cur = con.cursor()
    for row in cur.execute(
        """
        select * from resources
        where created != -1 and deleted != -1
        """
    ).fetchall():
        arn, iam, created, deleted = row
        logging.info(
            "ARN %s created %s by %s deleted %s",
            arn,
            tsfmt(created),
            iam,
            tsfmt(deleted),
        )
    con.close()


def iso8601_to_ts(iso8601: str) -> int:
    """
    Convert an ISO8601 string to Unix timestamp.
    Args:
        iso8601: Date/time string to parse
    """
    return int(dt.datetime.strptime(iso8601, "%Y-%m-%dT%H:%M:%SZ").timestamp())


def load(fndb: str, fnjson: str) -> Tuple[Connection, Cursor]:
    """
    Create and populate database from event records.
    Args:
        fndb: Database filename
        jnjson: Raw JSON input filename
    """
    con = connect(fndb)
    cur = con.cursor()
    create_tables(con=con, cur=cur)
    i = 0
    for r in records(fnjson):
        i += 1
        if i > 1000:
            break
        if existing := cur.execute(
            "select * from resources where arn = ?", (r.arn,)
        ).fetchall():
            resource_row_update(cur=cur, old=existing[0], new=r)
        else:
            resource_row_insert(cur=cur, new=r)
    con.commit()
    con.close()
    return con, cur


def main() -> None:
    """
    The main entry point.
    """
    setup_logging()
    if sys.argv[1] == "load":
        logging.info("Loading database from raw JSON")
        if os.path.exists(FNDB):
            logging.info("Removing %s", FNDB)
            os.unlink(FNDB)
        load(FNDB, FNJSON)
    elif sys.argv[1] == "exist-between":
        t0, t1 = map(iso8601_to_ts, [sys.argv[2], sys.argv[3]])
        exist_between(FNDB, t0, t1)
    elif sys.argv[1] == "finite-resources":
        finite_resources(FNDB)
    elif sys.argv[1] == "reads-writes":
        reads_writes(FNDB)


def reads_writes(fndb: str) -> None:
    """
    Report reads/writes for each resource (NOT WHAT WAS REQUESTED)
    Args:
        fndb: Database filename
    """
    con = connect(fndb)
    cur = con.cursor()
    for row in cur.execute("select * from resources").fetchall():
        arn, _, _, _ = row
        logging.info("ARN %s", arn)
    con.close()


def records(fn: str) -> Generator:
    """
    Stream records from structured JSON, ignoring "uninteresting" ones.
    Args:
        fn: The raw input JSON filename
    """
    with open(fn, "r", encoding="utf-8") as f:
        for record in ijson.items(f, "Records.item"):
            event_type = record["eventType"]
            if event_type != "AwsApiCall":
                # Assume only API calls that include resources are of interest.
                logging.debug("Ignoring non-API call event type %s", event_type)
                continue
            if "resources" not in record:
                # Assume API calls of interest relate to specific resources.
                logging.debug("Event type %s has no resource(s)", event_type)
                continue
            if record.get("errorCode", None):
                # Assume API calls of interest were not met with errors.
                logging.debug("Ignoring API call with error")
                continue
            # Yield info for each resoruce affected by this event.
            for resource in record["resources"]:
                arn = resource["ARN"]
                if arn == "*":
                    arn = "arn:aws:{service}:{region}:{account}:{type}".format(
                        service=record["eventSource"].split(".")[0],
                        region=record["awsRegion"],
                        account=resource["accountId"],
                        type=record["eventName"],  # guessing
                    )
                yield ns(
                    arn=arn,
                    iam=record["userIdentity"]["arn"],
                    name=record["eventName"],
                    ro=record["readOnly"],
                    ts=iso8601_to_ts(record["eventTime"]),
                )


def resource_row_insert(cur: Cursor, new: ns) -> None:
    """
    Insert a new resource row.
    Args:
        cur: The database cursor
        new: The new record to insert
    """
    created = -1 if new.ro else new.ts
    deleted = new.ts if "Delete" in new.name else -1
    cur.execute(
        """
        insert into resources (arn, iam, created, deleted)
        values (?, ?, ?, ?)
        """,
        (new.arn, new.iam, created, deleted),
    )
    logging.info("Inserted %s", new.arn)


def resource_row_update(cur: Cursor, old: Tuple, new: ns) -> None:
    """
    Update an existing resource row.
    Args:
        cur: The database cursor
        old: The existing database row
        new: The basis record for the update
    """
    arn, _, created, deleted = old
    created = created if new.ro else new.ts
    deleted = new.ts if "Delete" in new.name else deleted  # likely naive
    cur.execute(
        """
        update resources
        set created = ?, deleted = ?
        where arn = ?
        """,
        (created, deleted, arn),
    )
    logging.info("Updated %s: created %s deleted %s", arn, created, deleted)


def setup_logging() -> None:
    """
    Sets up logging with ISO8601 timestamps and UTC times.
    """
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        format="[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        level=logging.INFO,
    )


def tsfmt(ts: int) -> str:
    """
    Format the given Unit timestamp as an ISO860 string.
    Args:
        ts: The timestamp
    """
    return (
        "<unknown>"
        if ts == -1
        else dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


main()
