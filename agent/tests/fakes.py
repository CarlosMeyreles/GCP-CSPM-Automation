"""A stand-in for the BigQuery client so tests need no network or credentials."""


class FakeJob:
    def __init__(self, rows):
        self._rows = rows

    def result(self):
        return self._rows


class FakeBQ:
    def __init__(self, rows=None, error=None, insert_errors=None):
        self.rows = rows or []
        self.error = error
        self.insert_errors = insert_errors or []
        self.calls = []
        self.audit = []

    def query(self, sql, job_config=None):
        if self.error:
            raise self.error
        self.calls.append((sql, job_config))
        return FakeJob(self.rows)

    def insert_rows_json(self, table, rows):
        self.audit.append((table, rows))
        return self.insert_errors
