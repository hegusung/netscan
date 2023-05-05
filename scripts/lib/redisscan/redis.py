import socket
import traceback
import logging

import redis

from utils.utils import AuthFailure

class Redis:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None

    def url(self):
        return 'redis://%s:%d' % (self.hostname, self.port)

    def disconnect(self):
        # no disconnect on redis-py
        pass

    def auth(self, password=None):
        success = False

        try:
            self.conn = redis.StrictRedis(host=self.hostname, port=self.port, password=password, socket_timeout=self.timeout, socket_connect_timeout=self.timeout)

            version = self.conn.info()["redis_version"]

            return True, version
        except redis.exceptions.InvalidResponse as e:
            return False, None
        except redis.exceptions.ResponseError as e:
            return False, None
        except redis.exceptions.AuthenticationError as e:
            return False, None

    def list_databases(self):
        databases = []
        for database in self.conn.database_names():
            collections = []
            for collection in self.conn[database].collection_names():
                collections.append(collection)
            databases.append({'name': database, 'collections': collections})

        return databases

