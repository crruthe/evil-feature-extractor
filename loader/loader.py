import logging
import pandas as pd
import re
from rq import Queue
from redis import Redis
from host_process import host_process
from elasticsearch import Elasticsearch
from elasticsearch.helpers import *
from elasticsearch.client import IndicesClient
import argparse

CONFIG = {
    'mappings': {
        'appcompat': {
            'properties': {
                'instance_id': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'class_label': {
                    'type': 'string',
                    'index': 'not_analyzed',
                    'null_value': ''                
                },
                'predict': {
                    'type': 'float',
                    'index': 'not_analyzed',
                    'null_value': 0.0             
                },
                'hostname': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'run_order': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'last_modified': {
                    'type': 'date',
                    'index': 'not_analyzed'
                },
                'last_executed': {
                    'type': 'date',
                    'index': 'not_analyzed'
                },
                'path': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_size': {
                    'type': 'long',
                    'index': 'not_analyzed'
                },
                'file_executed': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'file_unc': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_drive': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_root': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_shortname': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_ext': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'file_name': {
                    'type': 'string',
                    'index': 'not_analyzed'
                },
                'f_path_uniq_hosts': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_recon_cluster': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_files_in_folder': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_neighbour_psexec': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_same_timestamp_different_name': {
                    'type': 'integer',
                    'index': 'not_analyzed',
                    'null_value': 0
                },
                'f_same_filesize_different_name': {
                    'type': 'integer',
                    'index': 'not_analyzed',
                    'null_value': 0
                },
                'f_shortname_ends_3264': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_path_depth': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_staging_directory': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_temp_dir': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_system32_dir': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_recon_cmd': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_users_dir': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                },
                'f_number_digits': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_root_length': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_shortname_length': {
                    'type': 'integer',
                    'index': 'not_analyzed'
                },
                'f_executable_archive': {
                    'type': 'boolean',
                    'index': 'not_analyzed'
                }
            }
        }
    }
}

# create a run order for all hosts i.e. maintain appcompat order
def create_run_order(val):
    val['run_order'] = range(len(val))
    return val

# since the chunk might be in the middle of a host, we need to find the end of the last full host
def last_host_idx(df):
    h1 = df.iloc[-1].hostname
    for idx in reversed(df.index):
        h2 = df.hostname[idx]
        if h2 != h1:
            return idx

# setup the elastic search index
def create_es_index(index_name):
    es = Elasticsearch()
    client = IndicesClient(es)

    # take this opportunity to create training index if it doesn't exist
    if not client.exists('appcompat-training'):
        client.create(index='appcompat-training', body=CONFIG)    

    
    if client.exists(index_name):
        raise Exception('Index already exists: {}'.format(index_name))
    client.create(index=index_name, body=CONFIG)

# do the work.
def main():
    parser = argparse.ArgumentParser(description="Parses appcompat CSV, extract features and load into Elasticsearch")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toggles verbose output")
    
    group = parser.add_argument_group()
    group.add_argument("read_file", help="Reads data from a file")
    group.add_argument("index_name", help="Elasticsearch index name (prepended with 'appcompat')")
    
    group.add_argument("--chunk_size", help="Set the size of the chunks, where bigger chunks use more memory, but too small with impact unique host features. Default is 250000.")
    group.add_argument("--compression", help="Input CSV file is compressed (uses Pandas method {'infer', 'gzip', 'bz2'})")
    
    
    args = parser.parse_args()

    if args.verbose:
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
                          
    input_file = args.read_file
    index_name = 'appcompat-{}'.format(args.index_name)
    
    if args.chunk_size:
        CHUNKSIZE = args.chunk_size
    else:
        # Number needs to be a large enough sample for unique paths per host to work
        CHUNKSIZE = 250000

    if args.compression:
        compression = args.compression
    else:
        compression = None

    logging.info('Creating elasticsearch index...')
    create_es_index(index_name)


    logging.info('Reading CSV...')
    chunk_iter = pd.read_csv(input_file, compression=compression, 
                             names=['hostname','last_modified','last_execution','path','file_size','file_executed','key_path'],
                             usecols=['hostname','last_modified','last_execution','path','file_size','file_executed'], 
                             header=0,
                             dtype=object, parse_dates=['last_modified','last_execution'], 
                             date_parser=lambda x: pd.to_datetime(x, format="%m/%d/%y %H:%M:%S"), 
                             chunksize=CHUNKSIZE)

    # Tell RQ what Redis connection to use
    redis_conn = Redis()
    q = Queue(connection=redis_conn)  # no args implies the default queue

    # iterable, but need to convert to iterator
    chunk_iter = iter(chunk_iter)

    more_chunks = True
    df = next(chunk_iter, None)
    while (more_chunks):
        # keep future chunk to check if we're at the end
        next_chunk = next(chunk_iter, None)

        # in order to prevent very small chunks, combine the last chunk with the second last chunk
        if next_chunk is None:
            more_chunks = False
        elif len(next_chunk) < CHUNKSIZE:
            df = pd.concat([df, next_chunk], ignore_index=True)
            more_chunks = False
        # otherwise, chop off the last hostname rows and append to next chunk
        else:
            idx = last_host_idx(df)
            last_host = df[idx+1:]
            df = df[:idx]
            next_chunk = pd.concat([last_host, next_chunk], ignore_index=True)

        # filter out missing hostname or path which are likely corrupted rows  
        df = df[df.hostname.notnull() & df.path.notnull()]

        # create run order per host    
        df = df.groupby('hostname').apply(create_run_order)

        # map Yes/No to True/False
        df['file_executed'] = df['file_executed'].map({'True': True, 'Yes': True, 'False': False, 'No': False})

        # convert path to lowercase
        df['path'] = df['path'].str.lower()

        # convert UNC\vmware-host\Shared Folders\Test\blah.exe -> \\host\vmware-host\...
        df['path'] = df['path'].str.replace(r'^unc', '\\\\', 1)

        # remove \??\ from \??\c:\Test\blah.exe
        df['path'] = df['path'].str.replace(r'^{}'.format(re.escape('\\??\\')), '', 1)

        # calculate many hosts this path has been seen 
        grp_path = df.groupby('path')
        df_tmp = grp_path['hostname'].nunique().reset_index()
        df_tmp.columns = ['path','f_path_unique_hosts']
        df = pd.merge(df, df_tmp, how='left', on=['path'])

        # Break up into smaller batches to distribute across availables workers
        BATCHSIZE = 50
        
        hosts = df.groupby('hostname')

        result_hosts = []
        for hostname, host_data in hosts:
            # batch up results and submit to queue
            result_hosts.append(host_data)
            if len(result_hosts) >= BATCHSIZE:
                logging.debug('Loading batch into Redis queue (size: {})...'.format(len(result_hosts)))
                q.enqueue(host_process, index_name, result_hosts)
                result_hosts = []
        if len(result_hosts) > 0:
            logging.debug('Loading batch into Redis queue (size: {})...'.format(len(result_hosts)))
            q.enqueue(host_process, index_name, result_hosts)

        # process the next chunk
        df = next_chunk

if __name__ == '__main__':
    main()