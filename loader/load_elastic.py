from elasticsearch import Elasticsearch
from elasticsearch.helpers import *

def load_elastic(index_name, hosts):
    es = Elasticsearch()
    actions = []

    for host in hosts:
        for i in host.iterrows():
            action = {
                "_index": index_name,
                "_type": "appcompat",
                "_source": i[1].to_json(date_format='iso')
            }

            actions.append(action)

    if len(actions) > 0:
        bulk(es, actions)