from neo4j import GraphDatabase
from utils.config import Config
from utils.db import DB
from utils.db import Elasticsearch

# Neo4j connection details
NEO4J_URI = "bolt://localhost:7687"  # Change if your DB is remote or uses a different port
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "your_password"

# Cypher query (example: mark users as owned)
cypher_query = """
WITH ['DOMAIN\\user1', 'DOMAIN\\user2'] AS ownedUsers
MATCH (u:User)
WHERE u.name IN ownedUsers
SET u.system_tags = coalesce(u.system_tags, []) + 'owned'
"""

def set_owned(session):

    neo4j_host = Config.config.get('Neo4J', 'host')
    neo4j_username = Config.config.get('Neo4J', 'username')
    neo4j_password = Config.config.get('Neo4J', 'password')

    print(neo4j_host)

    # Query domain hosts with admins
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_host"        }},
            { "match": { "session.keyword": session }},
            { "exists": { "field": "admin" }},
          ],
          "filter": [
          ]
        }
      },
    }


    owned_hosts = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        owned_hosts.append("%s.%s" % (source['hostname'].upper(), source['domain'].upper()))

    print(owned_hosts)
    if len(owned_hosts) != 0:
        print("Setting %d computers as Owned..." % len(owned_hosts))
        cypher_query = "WITH ['%s'] AS ownedUsers MATCH (u:Computer) WHERE u.name IN ownedUsers AND (u.system_tags IS NULL OR NOT 'owned' IN u.system_tags) SET u.system_tags = coalesce(u.system_tags, '') + ' owned'" % "', '".join(owned_hosts)

        driver = GraphDatabase.driver("bolt://%s:7687" % neo4j_host, auth=(neo4j_username, neo4j_password))
        with driver.session() as neo4j_session:
            print(cypher_query)
            neo4j_session.run(cypher_query)
        driver.close()
        print("Query executed successfully.")

    owned_users = []
    # Query domain passwords
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_password"        }},
            { "match": { "session.keyword": session }},
          ],
          "filter": [
          ]
        }
      },
    }



    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        owned_users.append("%s@%s" % (source['username'].upper(), source['domain'].upper()))
        
    # Query domain passwords
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_hash"        }},
            { "match": { "session.keyword": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        owned_users.append("%s@%s" % (source['username'].upper(), source['domain'].upper()))



    if len(owned_users) != 0:
        print("Setting %d users as Owned..." % len(owned_users))
        cypher_query = "WITH ['%s'] AS ownedUsers MATCH (u:User) WHERE u.name IN ownedUsers AND (u.system_tags IS NULL OR NOT 'owned' IN u.system_tags) SET u.system_tags = coalesce(u.system_tags, '') + ' owned'" % "', '".join(owned_users)

        driver = GraphDatabase.driver("bolt://%s:7687" % neo4j_host, auth=(neo4j_username, neo4j_password))
        with driver.session() as neo4j_session:
            print(cypher_query)
            neo4j_session.run(cypher_query)
        driver.close()
        print("Query executed successfully.")
