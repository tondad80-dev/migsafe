"""Opt-in transaction context for SQL files wrapped by a migration runner."""
import json

import pytest

from migsafe.cli import main
from migsafe.rules import check_files, check_sql

INDEX = "CREATE INDEX CONCURRENTLY email_idx ON users (email)"
SQL = "SET lock_timeout='3s';\n" + INDEX + ";"


def transaction_findings(sql):
    return [
        finding for finding in check_sql(sql, assume_transactional=True).findings
        if finding.rule == "concurrent-index-in-transaction"
    ]


def test_check_sql_default_and_explicit_false_preserve_autocommit():
    assert check_sql(SQL).findings == []
    assert check_sql(SQL, assume_transactional=False).findings == []


def test_check_files_default_and_explicit_false_preserve_autocommit():
    assert check_files({"migration.sql": SQL}).findings == []
    assert check_files({"migration.sql": SQL}, assume_transactional=False).findings == []


def test_check_sql_assumes_transaction_and_preserves_filename_and_location():
    report = check_sql(SQL, "migration.sql", assume_transactional=True)
    assert report.files == ["migration.sql"]
    assert report.statements == 2
    assert [(f.rule, f.severity, f.line, f.statement) for f in report.findings] == [
        ("concurrent-index-in-transaction", "high", 2, INDEX)
    ]


def test_check_files_restarts_assumed_transaction_for_each_file():
    first = "SET lock_timeout='3s'; COMMIT; " + INDEX + ";"
    second_index = "CREATE UNIQUE INDEX CONCURRENTLY second_idx ON users (name)"
    report = check_files(
        {"first.sql": first, "second.sql": "SET lock_timeout='3s'; " + second_index + ";"},
        assume_transactional=True,
    )
    assert report.files == ["first.sql", "second.sql"]
    assert [f.statement for f in report.findings] == [second_index]


@pytest.mark.parametrize("ending", [
    "COMMIT", "COMMIT WORK", "COMMIT TRANSACTION",
    "ROLLBACK", "ROLLBACK WORK", "ROLLBACK TRANSACTION", "END", "ABORT",
    "COMMIT AND NO CHAIN", "COMMIT WORK AND NO CHAIN",
    "ROLLBACK AND NO CHAIN", "ROLLBACK TRANSACTION AND NO CHAIN",
])
def test_explicit_end_releases_assumed_transaction_for_remaining_file(ending):
    assert transaction_findings("SET lock_timeout='3s'; " + ending + "; " + INDEX + ";") == []


@pytest.mark.parametrize("begin", ["BEGIN", "BEGIN WORK", "START TRANSACTION"])
def test_begin_inside_assumed_transaction_does_not_nest(begin):
    sql = "SET lock_timeout='3s'; " + begin + "; COMMIT; " + INDEX + ";"
    assert transaction_findings(sql) == []


@pytest.mark.parametrize("rollback", [
    "ROLLBACK TO before_index",
    "ROLLBACK TO SAVEPOINT before_index",
    "ROLLBACK WORK TO SAVEPOINT before_index",
    "ROLLBACK TRANSACTION TO SAVEPOINT before_index",
])
def test_rollback_to_savepoint_preserves_assumed_transaction(rollback):
    sql = "SET lock_timeout='3s'; SAVEPOINT before_index; " + rollback + "; " + INDEX + ";"
    assert [f.statement for f in transaction_findings(sql)] == [INDEX]


@pytest.mark.parametrize("ending", [
    "COMMIT AND CHAIN", "COMMIT WORK AND CHAIN",
    "ROLLBACK AND CHAIN", "ROLLBACK TRANSACTION AND CHAIN",
])
def test_and_chain_keeps_assumed_transaction_active(ending):
    sql = "SET lock_timeout='3s'; " + ending + "; " + INDEX + ";"
    assert [f.statement for f in transaction_findings(sql)] == [INDEX]


def test_explicit_begin_can_reopen_after_assumed_transaction_ends():
    sql = "SET lock_timeout='3s'; COMMIT; BEGIN; " + INDEX + "; COMMIT;"
    assert [f.statement for f in transaction_findings(sql)] == [INDEX]


@pytest.mark.parametrize("prefix", [
    "-- COMMIT; ROLLBACK;\n/* END; ABORT; */",
    "SELECT 'COMMIT; ROLLBACK;';",
    "CREATE FUNCTION f() RETURNS text AS $$ BEGIN RETURN 'COMMIT;'; END $$ LANGUAGE plpgsql;",
])
def test_end_in_comment_literal_or_function_does_not_release_assumption(prefix):
    sql = "SET lock_timeout='3s';\n" + prefix + "\n" + INDEX + ";"
    assert [f.statement for f in transaction_findings(sql)] == [INDEX]


def test_concurrent_index_on_new_table_is_still_flagged_when_assumed():
    sql = "SET lock_timeout='3s';\nCREATE TABLE audit (id int);\nCREATE INDEX CONCURRENTLY audit_idx ON audit (id);"
    assert [(f.severity, f.line) for f in transaction_findings(sql)] == [("high", 3)]


def test_assumption_does_not_change_other_findings():
    sql = "SET lock_timeout='3s'; DROP TABLE old; ALTER TABLE users ADD COLUMN age int NOT NULL;"
    regular = check_sql(sql)
    assumed = check_sql(sql, assume_transactional=True)
    assert [f.as_dict() for f in regular.findings] == [f.as_dict() for f in assumed.findings]


@pytest.mark.parametrize("assume, expected_exit", [(False, 0), (True, 2)])
def test_cli_flag_controls_actual_json_findings_and_exit_code(tmp_path, capsys, assume, expected_exit):
    migration = tmp_path / "migration.sql"
    migration.write_text(SQL, encoding="utf-8")
    args = ["check", str(migration), "--json"]
    if assume:
        args.append("--assume-transactional")
    assert main(args) == expected_exit
    report = json.loads(capsys.readouterr().out)
    assert report["worst"] == ("high" if assume else "none")
    assert [f["rule"] for f in report["findings"]] == (
        ["concurrent-index-in-transaction"] if assume else []
    )


def test_cli_fail_on_none_keeps_assumed_transaction_findings(tmp_path, capsys):
    migration = tmp_path / "migration.sql"
    migration.write_text(SQL, encoding="utf-8")
    assert main(["check", str(migration), "--assume-transactional", "--json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [f["rule"] for f in report["findings"]] == ["concurrent-index-in-transaction"]
