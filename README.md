# CloudTrail Event Analysis

## Setup

- Run `make env` to create the virtual environment, and `source activate-env` to activate it thereafter.
- Run `make test` to format and perform quality checks on the code.

## Using

- Ensure `cloudtrail-2022-03.json` is present in the local directory.
- Run `python analyze.py load` to recreate the database from raw JSON.
- Run `python analyze.py exit-between <t0> <t1>` to show resources that existed betweent times `t0` and `t1`, expressed as `YYYY-MM-DDTHH:MM:SSZ` strings.
- Run `python analyze.py finite-resources` to show resources created and deleted within the scope of the raw JSON input's time bounds.
- Run `python analyze.py reads-writes` to show total reads and writes for each resource.

## TODO

- Split up long functions
- Write unit tests
