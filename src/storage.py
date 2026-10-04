#SQL and database storage.
import sqlite3
from datetime import datetime
from action import AgentAction

class EventStorage:
    def __init__(self, database_file="agentshield.db"):
        self.database_file = database_file
        self._initialize_database()

    def _initialize_database(self):
        connection = sqlite3.connect(self.database_file)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                result TEXT NOT NULL
            )
        """)

        connection.commit()
        connection.close()

    def save_event(self, run_id, action):
        connection = sqlite3.connect(self.database_file)

        connection.execute("""
            INSERT INTO events (
                run_id,
                agent_name,
                action_type,
                resource,
                timestamp,
                result
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            action.agent_name,
            action.action_type,
            action.resource,
            action.timestamp.isoformat(),
            action.result
        ))

        connection.commit()
        connection.close()

    def get_events(self, agent_name=None, run_id=None, exclude_run_id=None, since=None):
        connection = sqlite3.connect(self.database_file)

        if agent_name and run_id:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                WHERE agent_name = ?
                AND run_id = ?
                ORDER BY id
            """, (agent_name, run_id))

        elif agent_name and exclude_run_id:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                WHERE agent_name = ?
                AND run_id != ?
                ORDER BY id
            """, (agent_name, exclude_run_id))

        elif agent_name:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                WHERE agent_name = ?
                ORDER BY id
            """, (agent_name,))

        elif run_id:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                WHERE run_id = ?
                ORDER BY id
            """, (run_id,))

        else:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                ORDER BY id
            """)

        rows = cursor.fetchall()
        connection.close()

        events = []

        for row in rows:
            events.append(
                AgentAction(
                    agent_name=row[0],
                    action_type=row[1],
                    resource=row[2],
                    timestamp=datetime.fromisoformat(row[3]),
                    result=row[4]
                )
            )

        if since is not None:
            events = [
                event
                for event in events
                if event.timestamp >= since
            ]

        return events

    def get_event_runs(self, agent_name=None, exclude_run_id=None, since=None):
        connection = sqlite3.connect(self.database_file)

        query = """
            SELECT run_id, agent_name, action_type, resource, timestamp, result
            FROM events
            WHERE 1 = 1
        """

        parameters = []

        if agent_name:
            query += " AND agent_name = ?"
            parameters.append(agent_name)

        if exclude_run_id:
            query += " AND run_id != ?"
            parameters.append(exclude_run_id)

        query += " ORDER BY run_id, id"

        cursor = connection.execute(
            query,
            parameters
        )

        rows = cursor.fetchall()
        connection.close()

        runs = {}

        for row in rows:
            run_id = row[0]

            event = AgentAction(
                agent_name=row[1],
                action_type=row[2],
                resource=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                result=row[5]
            )

            if since is not None and event.timestamp < since:
                continue

            if run_id not in runs:
                runs[run_id] = []

            runs[run_id].append(event)

        return list(runs.values())
    