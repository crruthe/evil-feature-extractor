import ntpath
import pandas as pd
from rq import Queue
from redis import Redis
from load_elastic import load_elastic

'''
Does the filename end with 32, 64, 86 (eg. wce32.exe)?
Threat actors like to label their tools for this
'''
def shortname_ends_3264(shortname):
    for i in ['32','64','86']:
        if shortname.endswith(i):
            return True
    return False

'''
How depth is the path structure?
Threat actors rarely use deep paths for tools (however, backdoors may have deep paths)
'''
def path_depth(root):
    if root == '\\':
        return 0
    else:
        return root.count('\\')

'''
Is the file in a known staging directory?
Threat actors like to store their tools in preexisting directories and that are preferably empty
'''
def staging_directory(root):
    dirs = ['\\$recycle.bin', 
              '\\programdata', 
              '\\windows\\debug', 
              '\\recycler', 
              '\\system volume information', 
              '\\intel', 
              '\\hp', 
              '\\dell', 
              '\\recovery', 
              '\\perflogs', 
              '\\drivers']
    if root in dirs:
        return True
    
    for i in dirs:
        if root.startswith(i+'\\'):
            return True
    return False

'''
Is the file in a temp directory?
Threat actors like to write to temp directories (always has write permissions)
'''
def temp_dir(root):
    return root.endswith('\\temp') or '\\temp\\' in root

'''
Is the file in the system32 directory?
Threat actors like to store backdoors in the system32 directory
'''
def system32_dir(root):
    return root.endswith('\\system32') or '\\system32\\' in root

'''
Is the file a windows recon file?
This is required for clustering of recon files
'''
def recon_cmd(file_root, file_shortname, file_ext):
    cmds = ['net',
            'ping',
            'tasklist',
            'ipconfig',
            'quser',
            'query',
            'netstat',
            'whoami',
            'qwinsta',
            'dsquery',
            'arp',
            'hostname',
            'systeminfo',
            'nltest',
            'cscript',
            'at',
            'ftp',
            'powershell',
            'wmic',
            'nslookup',
            'tracert',
            'route']
    for i in ['\\system32']: #'\\syswow64', '\\sysnative']:
        if (file_root.endswith(i) or i in file_root) and file_ext == '.exe' and file_shortname in cmds:
            return True
    return False 

'''
Is the file in the users directory?
Common for 1st stage backdoors to be in this directory and hence, threat actor may use tools here as well (cwd)
'''
def users_dir(root):
    return root.startswith('\\users')

'''
How many digits in path?
Never seen more than 2 or 3. This will filter at random generated paths (d:\4563bb32f7060ac2f373fe2d81d0\install.exe)
'''
def number_digits(path):
    return sum(c.isdigit() for c in path)

'''
Is the file part of an extracted archive?
Common attack vector for user to run executable archives
'''
def executable_archive(root):
    for i in ['7zs','rarsfx']:
        if i in root:
            return True
    return False
    
'''
Split up the path and extract the features
'''    
def extract_path_features(full_path):
    
    unc,path = ntpath.splitunc(full_path)
    drive = ''
    if not unc:
        drive,path = ntpath.splitdrive(full_path)
        
    root,filename = ntpath.split(path)
    shortname,ext = ntpath.splitext(filename)
    
    # convert \sysvol\windows to sysvol:\windows
    if not drive and root.startswith('sysvol'):
        drive = 'sysvol:'
        root = root.replace('sysvol', '', 1)
                
    return pd.Series([
            str(unc),
            str(drive),
            str(root),
            shortname,
            ext[1:],   # remove '.'
            filename,
            shortname_ends_3264(shortname),
            path_depth(root),
            len(root),
            len(shortname),
            staging_directory(root),
            temp_dir(root),
            system32_dir(root),
            recon_cmd(root, shortname, ext),
            users_dir(root),
            number_digits(root+shortname),
            executable_archive(root)])

'''
Is the file within a cluster of windows recon commands?
Threat actors will typically run recon commands once they connect to their backdoor
'''
def recon_cluster(host_data):
    recon_list = [0] * len(host_data)
    run_order_list = host_data[host_data.f_recon_cmd]['run_order'].tolist()
    
    if len(run_order_list) > 0:
        clusters = []
        # first cluster will contain at least the first element
        cluster = [run_order_list[0]]
        # iterator through the run_order_list and group by clusters
        for i in xrange(len(run_order_list)-1):
            # if the distance between two points is less-than-equal 5, it's part of the cluster 
            if run_order_list[i+1] - run_order_list[i] <= 5:
                cluster.append(run_order_list[i+1])
            # otherwise we create a new cluser
            else:
                clusters.append(cluster)
                cluster = [run_order_list[i+1]]
        clusters.append(cluster)
        for i in clusters:
            start = max(0, min(i)-3)
            end = min(len(recon_list), max(i)+3)
            for j in xrange(start,end):
                recon_list[j] = len(i)
    return pd.Series(recon_list)

'''
Is the file neighboured with psexec?
Common lateral movement technique is to use psexec, which will have a new psexesvc service close by
'''
def neighbour_psexec(host_data):
    recon_list = [False] * len(host_data)
    run_order_list = host_data[host_data.file_shortname == 'psexesvc']['run_order'].tolist()
    
    if len(run_order_list) > 0:
        for i in run_order_list:
            start = max(0, i-2)
            end = min(len(recon_list), i+2)
            for j in xrange(start,end):
                recon_list[j] = True
    return pd.Series(recon_list)

'''
How many files have been seen in this directory?
Threat actors are likely to run more than one tool in any given path
'''
def files_per_folder(host_data):
    g = host_data.groupby('file_root')
    tmp = g['file_name'].nunique().reset_index()
    tmp.columns = ['file_root','f_files_in_folder']
    return pd.merge(host_data, tmp, how='left', on=['file_root'])

'''
Do any files share a timestamp but have different names?
This can be used to detect timestomping, e.g. bad.exe timestomped from cmd.exe
'''
def same_timestamp_different_name(host_data):
    g = host_data.groupby('last_modified')
    tmp = g['file_name'].nunique().reset_index()
    tmp.columns = ['last_modified','f_same_timestamp_different_name']
    return pd.merge(host_data, tmp, how='left', on=['last_modified'])

'''
Do any files share a filesize but have different names?
This can be used to detect backdoors or tools used in multiple staging directories
'''
def same_filesize_different_name(host_data):
    g = host_data.groupby('file_size')
    tmp = g['file_name'].nunique().reset_index()
    tmp.columns = ['file_size','f_same_filesize_different_name']
    return pd.merge(host_data, tmp, how='left', on=['file_size'])

def host_process(index_name, hosts):
    columns = ['file_unc','file_drive','file_root','file_shortname','file_ext','file_name',
               'f_shortname_ends_3264','f_path_depth','f_root_length','f_shortname_length',
               'f_staging_directory','f_temp_dir','f_system32_dir','f_recon_cmd','f_users_dir',
               'f_number_digits','f_executable_archive']

    # Tell RQ what Redis connection to use
    redis_conn = Redis()
    q = Queue('high',connection=redis_conn)  # high queue to get data out of memory faster

    result_hosts = []
    for host_data in hosts:
        x = host_data['path'].apply(extract_path_features)
        x.columns = columns
        host_data = host_data.join(x)

        # make sure we use the actual appcompat correct order
        host_data = host_data.sort_values(by='run_order')

        # reset the index, as this will allows us to add columns of lists easily
        host_data = host_data.reset_index()
        del host_data['index'] # delete the old index column

        host_data['f_recon_cluster'] = recon_cluster(host_data)
        host_data['f_neighbour_psexec'] = neighbour_psexec(host_data)
        host_data = files_per_folder(host_data)
        host_data = same_timestamp_different_name(host_data)
        host_data = same_filesize_different_name(host_data)

        # create empty columns for later
        host_data['class_label'] = ''
        host_data['predict'] = 0.0

        # default values
        host_data['f_same_timestamp_different_name'] = host_data['f_same_timestamp_different_name'].fillna(0)
        host_data['f_same_filesize_different_name'] = host_data['f_same_filesize_different_name'].fillna(0)

        # no longer need this data, might as well remove it and save some space
        for i in ['file_unc','file_drive','file_root','file_shortname','file_ext','file_name']:
            del host_data[i]

        # batch up results and submit to queue
        result_hosts.append(host_data)

    if len(result_hosts) > 0:
        q.enqueue(load_elastic, index_name, result_hosts)


