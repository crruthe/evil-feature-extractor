from flask import render_template
from flask import jsonify
from flask import request
from flask import g
from flask import abort
from app import app
from elasticsearch import Elasticsearch
from elasticsearch.client import IndicesClient
from elasticsearch.exceptions import RequestError
from rq import Queue
from redis import Redis


es = Elasticsearch()

columns = [
    '_id',
    '_index',
    'class_label',
    'hostname',
    'predict',
    'path',
    'last_modified',
    'last_execution',
    'file_size',
    'file_executed',
    'f_neighbour_psexec',
    'f_shortname_ends_3264',
    'f_path_depth',
    'f_shortname_length',
    'f_staging_directory',
    'f_temp_dir',
    'f_system32_dir',
    'f_recon_cmd',
    'f_users_dir',
    'f_path_unique_hosts',
    'f_number_digits',
    'f_root_length',
    'f_executable_archive',
    'f_recon_cluster',
    'f_files_in_folder',
    'f_same_timestamp_different_name',
    'f_same_filesize_different_name'
]

def get_es_indices():
    es_idx = IndicesClient(es)
    indicies = es_idx.get('appcompat-*')
    result = []
    for index_name,v in indicies.iteritems():
        result.append((index_name,index_name,v['settings']['index']['creation_date']))
    return result


@app.route('/')
@app.route('/index')
def index():
    instances = get_es_indices()
    app.logger.debug(instances)
    return render_template('index.html',
        title='Home',
        dt_columns=columns,
        instances=instances)

@app.route('/api/entries', methods=['GET'])
@app.route('/api/entries/<string:index_name>', methods=['GET'])
def entries(index_name='appcompat-*'):
    draw = request.args.get('draw', -1, type=int)
    start = request.args.get('start', 0, type=int)
    length = request.args.get('length', 50, type=int)
    sort_idx = request.args.get('order[0][column]', 0, type=int)
    sort_direction = request.args.get('order[0][dir]', 'asc', type=str)
    search = request.args.get('search[value]', '', type=str)

    if sort_idx < 0 or sort_idx > len(columns):
        return abort(404)

    if sort_direction not in ['asc','desc']:
        return abort(404)

    sort_column = columns[sort_idx]

    if search:
        try:
            result = es.search(index=index_name, 
                doc_type='appcompat', 
                q=search, 
                size=length, 
                from_=start, 
                sort='{}:{},hostname:asc,run_order:asc'.format(sort_column, sort_direction))
        except RequestError as e:
            return jsonify(e.info), 500
    else:
        result = es.search(index=index_name, 
            doc_type='appcompat', 
            body={'query':{'match_all': {}}}, 
            size=length, 
            from_=start, 
            sort='{}:{},hostname:asc,run_order:asc'.format(sort_column, sort_direction))

    return jsonify({
            'data': result['hits']['hits'],
            'draw': draw,
            'recordsTotal': result['hits']['total'],
            'recordsFiltered': result['hits']['total'],
        })


@app.route('/api/label/<string:index_name>/<string:entry_id>', methods=['POST','DELETE'])
def label(index_name,entry_id):        
    if request.method == 'DELETE':
        delete_training_entry(index_name, entry_id)

        # clear the label
        label = ''
    elif request.method == 'POST': 
        label = request.form.get('label', '', type=str)
        if label not in ['evil','not_evil','suspicious']:
            return abort(404)
        store_training_entry(index_name, entry_id, label)
    else:
        abort(405)

    if (index_name != 'appcompat-training'):
        # update the entry in the index
        es.update(index=index_name, doc_type='appcompat', id=entry_id, body={'doc':{'class_label':label}})
    

    return jsonify({
        'result': 'successful'
        })

# remove the training entry
def delete_training_entry(index_name, entry_id):
    result = es.get(index='appcompat-training', doc_type='appcompat', id=entry_id, ignore=404)
    if result['found']:
        es.delete(index='appcompat-training', doc_type='appcompat', id=entry_id)    

# store a copy of the label in the training table
def store_training_entry(index_name, entry_id, label):
    # determine if the entry already exists
    result = es.get(index='appcompat-training', doc_type='appcompat', id=entry_id, ignore=404)
    if result['found']:
        # since it was found, just update the entry
        es.update(index='appcompat-training', doc_type='appcompat', id=entry_id, body={'doc':{'class_label':label}})
    else:
        # grab the data from the entry to copy
        result = es.get(index=index_name, doc_type='appcompat', id=entry_id)

        # modify the label
        result['_source']['class_label'] = label

        # store the new entry
        es.index(index='appcompat-training', doc_type='appcompat', body=result['_source'], id=entry_id)


@app.route('/api/entry_context/<string:index_name>/<string:entry_id>', methods=['GET'])
def entry_context(index_name,entry_id):
    entry = es.get(index=index_name, doc_type='appcompat', id=entry_id)
    query = {'bool':{
                'filter':[
                    {'term':{'hostname': entry['_source']['hostname']}}, 
                    {'range':{
                        'run_order': {
                            'gte':entry['_source']['run_order']-10,
                            'lte':entry['_source']['run_order']+10
                        }
                    }}
                ]
            }
        }
    result = es.search(index=index_name, 
        doc_type='appcompat', 
        body={'query':query}, 
        size=21, 
        sort='run_order:asc')
    return jsonify({'data':result['hits']['hits']})


@app.route('/api/reprocess', methods=['POST'])
@app.route('/api/reprocess/<string:index_name>', methods=['POST'])
def reprocess(index_name=None):
    redis_conn = Redis()
    q = Queue(connection=redis_conn)

    full_scan = request.form.get('full_scan', '', type=str)

    if not index_name:
        index_name = 'appcompat-*'

    job = q.enqueue('predict_data.update_predict', index_name, full_scan == 'true', timeout=3600)

    return jsonify({'result': 'successful', 'job_id': job.id})


@app.route('/api/job_status/<string:job_id>', methods=['GET'])
def job_status(job_id):
    redis_conn = Redis()
    q = Queue(connection=redis_conn)

    job = q.fetch_job(job_id)

    return jsonify({'result': 'successful', 'job_status': job.get_status()})
