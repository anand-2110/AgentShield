import sqlite3


class EventStorage:

    def __init__(self, database_file="agentshield.db"):
        self.database_file = database_file
        self._initialize_database()

    def _initialize_database(self):
        connection = sqlite3.connect(self.database_file)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                result TEXT NOT NULL
            )
        """)

        connection.commit()
        connection.close()

    def save_event(self, action):
        connection = sqlite3.connect(self.database_file)

        connection.execute("""
            INSERT INTO events (
                agent_name,
                action_type,
                resource,
                timestamp,
                result
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            action.agent_name,
            action.action_type,
            action.resource,
            action.timestamp.isoformat(),
            action.result
        ))

        connection.commit()
        connection.close()

    def get_events(self, agent_name=None):
        connection = sqlite3.connect(self.database_file)

        if agent_name:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                WHERE agent_name = ?
                ORDER BY id
            """, (agent_name,))
        else:
            cursor = connection.execute("""
                SELECT agent_name, action_type, resource, timestamp, result
                FROM events
                ORDER BY id
            """)

        events = cursor.fetchall()
        connection.close()

        return events


