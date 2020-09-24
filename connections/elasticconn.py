'''
    __G__ = "(G)bd249ce4"
    connection -> elastic
'''

from os import environ
from elasticsearch import Elasticsearch
from analyzer.settings import elastic_db
from analyzer.logger.logger import ignore_excpetion

if environ["analyzer_env"] == "local":
    ELASTIC_SEARCH = Elasticsearch([elastic_db])
elif environ["analyzer_env"] == "docker":
    ELASTIC_SEARCH = Elasticsearch([elastic_db])

def push_to_elastic(uuid, json):
    '''
    Not implemented
    '''
    with ignore_excpetion(Exception):
        res = ELASTIC_SEARCH.index(index='jsdoc', ignore=400, doc_type='doc', id=uuid, body=json)
    return res
