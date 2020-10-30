import socket
import traceback
import logging

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure, ConfigurationError

from utils.utils import AuthFailure

class Mongo:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None

    def url(self):
        return 'mongo://%s:%d' % (self.hostname, self.port)

    def disconnect(self):
        if self.conn != None:
            self.conn.close()
        self.conn = None

    def auth(self, username, password, database=''):
        success = False

        try:
            if username == None:
                url = 'mongodb://%s:%d/%s' % (self.hostname, self.port, database)
                self.conn = MongoClient(url, socketTimeoutMS=self.timeout*1000, connectTimeoutMS=self.timeout*1000, serverSelectionTimeoutMS=self.timeout*1000)
            else:
                url = 'mongodb://%s:%d/%s' % (self.hostname, self.port, database)
                self.conn = MongoClient(url, username=username, password=password, socketTimeoutMS=self.timeout*1000, connectTimeoutMS=self.timeout*1000, serverSelectionTimeoutMS=self.timeout*1000)


            version = self.conn.server_info()['version']

            return True, version
        except OperationFailure as e:
            return False, None
        except KeyError as e:
            return False, None

    def list_databases(self):
        databases = []
        for database in self.conn.database_names():
            collections = []
            for collection in self.conn[database].collection_names():
                collections.append(collection)
            databases.append({'name': database, 'collections': collections})

        return databases

