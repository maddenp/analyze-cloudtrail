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
from typing import Generator, Tuple

import ijson

FNDB = "cloudtrail.db"
FNJSON = "cloudtrail-2022-03.json"


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
        arn, created, deleted, _, _, _ = row
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
        "select * from resources where created != -1 and deleted != -1"
    ).fetchall():
        arn, created, deleted, iam, _, _ = row
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
    columns_resources = ", ".join(
        [
            "arn text primary key",
            "created int",
            "deleted int",
            "iam text",
            "reads int",
            "writes int",
        ]
    )
    cur.execute(f"create table resources({columns_resources})")
    con.commit()
    for r in records(fnjson):
        if existing := cur.execute(
            "select * from resources where arn = ?", (r.arn,)
        ).fetchall():
            arn, created, deleted, _, reads, writes = existing[0]
            created = created if r.ro else r.ts
            deleted = r.ts if "Delete" in r.name else deleted  # likely naive
            reads = reads + 1 if r.ro else reads
            writes = writes if r.ro else writes + 1
            cur.execute(
                """
                update resources set
                created = ?,
                deleted = ?,
                reads = ?,
                writes = ?
                where arn = ?
                """,
                (created, deleted, reads, writes, arn),
            )
            logging.info(
                "Updated %s: created %s deleted %s reads %s writes %s",
                arn,
                created,
                deleted,
                reads,
                writes,
            )
        else:
            created = -1 if r.ro else r.ts
            deleted = r.ts if "Delete" in r.name else -1
            reads = 1 if r.ro else 0
            writes = 0 if r.ro else 1
            cur.execute(
                "insert into resources values (?, ?, ?, ?, ?, ?)",
                (r.arn, created, deleted, r.iam, reads, writes),
            )
            logging.info("Added %s", r.arn)
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
        arn, _, _, _, reads, writes = row
        logging.info("ARN %s read %s times written %s times", arn, reads, writes)
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
