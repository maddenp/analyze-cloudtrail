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
from typing import Generator, List, Optional, Tuple

import ijson

FNDB = "cloudtrail.db"
FNJSON = "cloudtrail-2022-03.json"
UNKNOWN = -1


def db_access_record(cur: Cursor, new: ns) -> None:
    """
    Insert a new access row.
    Args:
        cur: The database cursor
        new: The new record to insert
    """
    vals = ns(
        arn=new.arn,
        name=new.name,
        iam=new.iam,
        ts=new.ts,
        read=1 if new.ro else 0,
        write=0 if new.ro else 1,
    )
    cur.execute(
        """
        insert into accesses (arn, name, iam, ts, read, write)
        values (?, ?, ?, ?, ?, ?)
        """,
        (vals.arn, vals.name, vals.iam, vals.ts, vals.read, vals.write),
    )
    logging.debug("Recorded access: %s", vals)


def db_resource_create(cur: Cursor, new: ns) -> None:
    """
    Insert a new resource row.
    Args:
        cur: The database cursor
        new: The new record to insert
    """
    created, deleted, earliest, latest = UNKNOWN, UNKNOWN, new.ts, new.ts
    if not new.ro:
        if "Delete" in new.name:  # likely naive
            deleted = new.ts
        else:
            created = new.ts
    vals = ns(
        arn=new.arn,
        iam=new.iam,
        created=created,
        deleted=deleted,
        earliest=earliest,
        latest=latest,
    )
    cur.execute(
        """
        insert into resources (arn, iam, created, deleted, earliest, latest)
        values (?, ?, ?, ?, ?, ?)
        """,
        (vals.arn, vals.iam, vals.created, vals.deleted, vals.earliest, vals.latest),
    )
    logging.debug("Created resource: %s", vals)


def db_resource_update(cur: Cursor, old: Tuple, new: ns) -> None:
    """
    Update an existing resource row.
    Args:
        cur: The database cursor
        old: The existing database row
        new: The basis record for the update
    """
    # TODO It's a bad sign that the structure of a new record read from JSON
    # and one read from the database are different. They should be consistent.
    arn, iam, created, deleted, earliest, latest = old
    if not new.ro:
        if "Delete" in new.name:  # likely naive
            deleted = new.ts if deleted == UNKNOWN or new.ts > deleted else deleted
        else:
            created = new.ts if created == UNKNOWN or new.ts < created else created
    earliest = min(earliest, new.ts)
    latest = max(latest, new.ts)
    vals = ns(
        arn=arn,
        iam=iam,
        created=created,
        deleted=deleted,
        earliest=earliest,
        latest=latest,
    )
    cur.execute(
        """
        update resources
        set created = ?, deleted = ?, earliest = ?, latest = ?
        where arn = ?
        """,
        (vals.created, vals.deleted, vals.earliest, vals.latest, vals.arn),
    )
    logging.debug("Updated resource: %s", vals)


def db_table_create(
    con: Connection, cur: Cursor, name: str, columns: List[str]
) -> None:
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


def db_tables_create(con: Connection, cur: Cursor) -> None:
    """
    Create database tables.
    Args:
        con: The database connection
        cur: The database cursor
    """
    # TODO Simplify logic elsewhere via default values here?
    # Resources table:
    db_table_create(
        con=con,
        cur=cur,
        name="resources",
        columns=[
            "arn text primary key",
            "iam text",
            "created int",
            "deleted int",
            "earliest int",
            "latest int",
        ],
    )
    # Access table:
    db_table_create(
        con=con,
        cur=cur,
        name="accesses",
        columns=[
            "arn text",
            "name text",
            "iam text",
            "ts int",
            "read int",
            "write int",
        ],
    )


def exist_between(fndb: str, lbound: int, ubound: int) -> None:
    """
    Find resources existing between the two times.
    Args:
        fndb: Database filename
        lbound: Initial time (Unix timestamp)
        ubound: Initial time (Unix timestamp)
    """
    con = connect(fndb)
    cur = con.cursor()
    for row in cur.execute(
        """
        select * from resources
        where ? <= latest and ? >= earliest
        order by earliest
        """,
        (lbound, ubound),
    ).fetchall():
        arn, _, _, _, earliest, latest = row
        logging.info(
            "Existed between %s and %s: ARN %s (earliest %s, latest %s)",
            tsfmt(lbound),
            tsfmt(ubound),
            arn,
            tsfmt(earliest),
            tsfmt(latest),
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
        where created != ? and deleted != ?
        """,
        (UNKNOWN, UNKNOWN),
    ).fetchall():
        arn, iam, created, deleted, _, _ = row
        logging.info(
            "Finite resource: %s to %s ARN %s created by %s",
            tsfmt(created),
            tsfmt(deleted),
            arn,
            iam,
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
    if os.path.exists(FNDB):
        logging.info("Removing %s", FNDB)
        os.unlink(FNDB)
    logging.info("Loading database from raw JSON...")
    con = connect(fndb)
    cur = con.cursor()
    db_tables_create(con=con, cur=cur)
    for record in records(fnjson):
        if existing := cur.execute(
            "select * from resources where arn = ?", (record.arn,)
        ).fetchall():
            db_resource_update(cur=cur, old=existing[0], new=record)
        else:
            db_resource_create(cur=cur, new=record)
        db_access_record(cur=cur, new=record)
    con.commit()
    con.close()
    return con, cur


def main() -> None:
    """
    The main entry point.
    """
    setup_logging()
    logging.info("Starting")
    if len(sys.argv) == 1:
        usage()
    if sys.argv[1] == "load":
        load(FNDB, FNJSON)
    elif sys.argv[1] == "exist-between":
        lbound, ubound = map(iso8601_to_ts, [sys.argv[2], sys.argv[3]])
        exist_between(FNDB, lbound, ubound)
    elif sys.argv[1] == "finite-resources":
        finite_resources(FNDB)
    elif sys.argv[1] == "reads-writes":
        lbound, ubound = map(iso8601_to_ts, [sys.argv[2], sys.argv[3]])
        min_aggregation = 5
        if ubound - lbound < (min_aggregation * 60):  # seconds
            logging.error("Minimum aggregation is %s minutes", min_aggregation)
            sys.exit(1)
        iam = None if len(sys.argv) < 5 else sys.argv[4]
        reads_writes(fndb=FNDB, lbound=lbound, ubound=ubound, iam=iam)
    else:
        usage()
    logging.info("Finished")


def reads_writes(
    fndb: str, lbound: int, ubound: int, iam: Optional[str] = None
) -> None:
    """
    Report reads/writes for each resource within given time range.
    Args:
        fndb: Database filename
        lbound: Initial Unix timestamp (inclusive lower bound)
        ubound: Final Unix timestamp (exclusive upper bound)
        iam: Optional IAM ARN to filter on
    """
    con = connect(fndb)
    cur = con.cursor()
    if iam:
        for row in cur.execute(
            """
            select arn, iam, sum(read), sum(write)
            from accesses
            where iam = ? and ts >= ? and ts < ?
            group by arn
            """,
            (iam, lbound, ubound),
        ).fetchall():
            arn, iam, reads, writes = row
            logging.info(
                "ARN %s accessed by %s: reads=%s writes=%s accesses=%s",
                arn,
                iam,
                reads,
                writes,
                reads + writes,
            )
    else:
        for row in cur.execute(
            """
            select arn, sum(read), sum(write)
            from accesses
            where ts >= ? and ts < ?
            group by arn
            """,
            (lbound, ubound),
        ).fetchall():
            arn, reads, writes = row
            logging.info(
                "ARN %s reads=%s writes=%s accesses=%s",
                arn,
                reads,
                writes,
                reads + writes,
            )
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
        if ts == UNKNOWN
        else dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def usage() -> None:
    """
    Print usage message and exit
    """
    print("Options:")
    for option in [
        "exist-between <earliest> <latest>",
        "finite-resources",
        "reads-writes [iam-arn]",
    ]:
        print(f"  - {option}")
    sys.exit(1)


if __name__ == "__main__":
    main()
