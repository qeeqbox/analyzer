from elasticsearch import Elasticsearch
from os import environ
from ..settings import elastic_db

if environ["analyzer_env"] == "local":
    es = Elasticsearch([elastic_db])
elif environ["analyzer_env"] == "docker":
   es = Elasticsearch([elastic_db])

def push_to_elastic(uuid,json):
	try:
		res = es.index(index='jsdoc', ignore=400, doc_type='doc', id=uuid, body=json)
	finally:
		return res