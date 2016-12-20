from sklearn.ensemble import ExtraTreesClassifier
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan, bulk
from rq import Queue
from redis import Redis
import os
import pickle

es = Elasticsearch()
columns = [
    'f_executable_archive',
    'f_files_in_folder',
    'f_neighbour_psexec',
    'f_number_digits',
    'f_path_depth',
    'f_path_unique_hosts',
    'f_recon_cluster',
    'f_recon_cmd',
    'f_root_length',
    'f_same_filesize_different_name',
    'f_same_timestamp_different_name',
    'f_shortname_ends_3264',
    'f_shortname_length',
    'f_staging_directory',
    'f_system32_dir',
    'f_temp_dir',
    'f_users_dir'
]

def train(index_name):
    data = []
    labels = []

    # setup the training data with features and consistent structure        

    # get all evil labeled data from the training set
    query = {'bool': {
            'filter': [
                {'term': {'class_label': 'evil'} }
            ]
        }
    }
    result = es.search(body={'query':query}, index="appcompat-training", doc_type="appcompat", size=1024)

    rows = []
    for i in result['hits']['hits']:
        row = []
        for j in columns:
            row.append(i['_source'][j])
        rows.append(row)
    data.extend(rows)
    num_evil = len(rows)

    # label these rows as "1 == evil"
    labels.extend([1]*num_evil)

    # get all non_evil labeled data from the training set
    query = {'bool': {
            'filter': [
                {'term': {'class_label': 'not_evil'} }
            ]
        }
    }
    result = es.search(body={'query':query}, index="appcompat-training", doc_type="appcompat", size=1024*3)

    # setup the training data with features and consistent structure        
    rows = []
    for i in result['hits']['hits']:
        row = []
        for j in columns:
            row.append(i['_source'][j])
        rows.append(row)
    data.extend(rows)
    num_not_evil = len(rows)

    # label these rows as "0 == not_evil"
    labels.extend([0]*num_not_evil)

    # Aim for a 1:3 ratio of evil to non evil
    num_other = 0
    if num_not_evil < (num_evil*3):

        # fill rest with random data (chances are its not evil) from index
        query = {
            'function_score' : {
                'query' : { 
                    'bool': {
                        'filter': [
                            {'term': {'class_label': ''} }
                        ]
                    } 
                },
                'random_score' : { 'seed': os.urandom(16).encode('hex')}
            }
        }

        size = (num_evil*3) - num_not_evil
        result = es.search(body={'query':query}, index=index_name, doc_type="appcompat", sort='_score:asc', size=size)

        # setup the training data with features and consistent structure        
        for i in result['hits']['hits']:
            row = []
            for j in columns:
                row.append(i['_source'][j])
            rows.append(row)
        data.extend(rows)
        num_other = len(rows)

        # label these rows as "0 == not_evil"
        labels.extend([0]*num_other)

    clf = ExtraTreesClassifier(n_estimators=1000, class_weight="balanced")
    clf = clf.fit(data, labels)
    print num_evil, num_not_evil, num_other

    with open('randomforest.dat', 'wb') as rf_file:
        pickle.dump(clf, rf_file)

    return clf

BATCHSIZE = 20000
def update_predict(index_name, full_scan=False):
    train_clf = train(index_name)

    redis_conn = Redis()
    q = Queue(connection=redis_conn)

    if full_scan:
        result = scan(es, index=index_name, doc_type='appcompat', query={'query':{'match_all': {}}})
    else:
        result = es.search(index=index_name, doc_type='appcompat', body={'query':{'match_all': {}}}, sort='predict:desc', size=10000)
        result = result['hits']['hits']

    rows = []
    for i in result:
        rows.append(i)

        if len(rows) > BATCHSIZE:
            q.enqueue(predict_data, train_clf, rows)
            rows = []

    if len(rows) > 0:
        q.enqueue(predict_data, train_clf, rows)

def predict_data(clf, rows):
    data = []
    for doc in rows:
        row = []
        for i in columns:
            row.append(doc['_source'][i])
        data.append(row)

    result = clf.predict_proba(data)

    actions = []
    for doc,predict in zip(rows,result):
        action = {
            '_op_type': 'update',
            "_index": doc['_index'],
            "_type": "appcompat",
            "_id": doc['_id'],
            "doc": {'predict': predict[1]}
        }

        actions.append(action)
        
    if len(actions) > 0:
        bulk(es, actions)
