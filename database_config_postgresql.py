import os


class PostgreSQLConfig:
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///helpdesk.db')


class DatabaseManager:
    def get_current_db_uri(self):
        return os.environ.get('DATABASE_URL', 'sqlite:///helpdesk.db')

    def get_database_info(self):
        uri = self.get_current_db_uri()
        db_type = 'PostgreSQL' if uri.startswith('postgresql') else 'SQLite'
        return {
            'type': db_type,
            'uri': uri,
            'status': 'connected',
        }
