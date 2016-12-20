# AppCompat SmartViewer

### Dependancies

* Redis
* Elasticsearch
* Flask (python)
* Pandas (python)
* elasticsearch (python)
* rq (python)

## Loader 
The loader will import an AppCompat CSV file, extract the features and push the results into Elasticsearch.

### Setup

Start the Redis server.

```
$ ./src/redis-server
```

Start the Elasticsearch server.

```
$ ES_HEAP_SIZE=4g ./bin/elasticsearch
```

Start rq workers, these workers will pull jobs from the Redis queue. They will pull from two queues:

* high - loads the data into elasticsearch (will need 1-2 workers)
* default - performs the feature extraction (can have 1 worker per CPU i.e. 4-8 workers)

```
$ cd ./loader

# Start 1-2 of these
$ rq worker -q high default

# Start 4-8 of these (or 1 per CPU)
$ rq worker -q default
```

### Usage
```
usage: loader.py [-h] [-v] [--chunk_size CHUNK_SIZE]
                 [--compression COMPRESSION]
                 read_file index_name

Parses appcompat CSV, extract features and load into Elasticsearch

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Toggles verbose output

  read_file             Reads data from a file
  index_name            Elasticsearch index name (will be prepended with 
                        'appcompat-')
  --chunk_size CHUNK_SIZE
                        Set the size of the chunks, where bigger chunks use
                        more memory, but too small with impact unique host
                        features. Default is 250000.
  --compression COMPRESSION
                        Input CSV file is compressed (uses Pandas method
                        {'infer', 'gzip', 'bz2'})
```

## Web Interface

Follow the setup steps for the loader i.e. Redis, Elasticsearch and workers.

Start the flask webapp.

```
$ cd ./flask
$ python run.py
```

Connect to the interface: [http://localhost:5000](http://localhost:5000)

## Features

* **f\_path\_unique\_hosts** - typical feature for stacking data. Paths that have been seen on majority of hosts are unlikely to be malicious.
* **f\_shortname\_ends\_3264** - does the filename end with 32, 64, 86. Attackers like to label their tools (eg. wce32.exe, x64.exe).
* **f\_path\_depth** - calculate the depth of the path structure. Attackers prefer not to use deep path structures for their tools (however, backdoors may have deep paths).
* **f\_staging\_directory** - is the file in a known staging directory?
Attackers like to store their tools in preexisting directories and that are preferably empty.
* **f\_temp\_dir** - is the file in a temp directory? Attackers like to write to temp directories as they always have write permissions.
* **f\_system32\_dir** - is the file in the system32 directory? Attackers like to store backdoors in the system32 directory.
* **f\_recon\_cmd** - is the file a windows file commonly used for recon by attackers? This feature is used later for recon clusters.
* **f\_users\_dir** - is the file in the users directory? Common for 1st stage backdoors to be in this directory and hence, attacker may use tools here as well (e.g. current working directory)
* **f\_number\_digits** - how many digits in path? Used to filter out noise, since attackers generally don't use more than a few digits. This will filter at random generated paths (d:\4563bb32f7060ac2f373fe2d81d0\install.exe).
* **f\_executable\_archive** - is the file part of an extracted archive (RarSFX, 7z executable)? Common attack vector for user to run executable archives (PlugX).
* **f\_shortname\_length** - how long is the filename? Attackers like to use short names (e.g. 1.exe, w.exe).
* **f\_root\_length** - how long is the directory structure? Attackers are unlikely to use long directory names.
* **f\_recon\_cluster** - this looks for clusters of recon commands. Very common for attackers to run a combination of commands (e.g. whoami, quser, tasklist).
* **f\_neighbour\_psexec** - this looks for commands adjacent to the psexec service. Attackers commonly use PsExec to perform lateral movement.
* **f\_same\_timestamp\_different\_name** - do any files share a timestamp but have different names? This can be used to detect timestomping (e.g. bad.exe timestomped from cmd.exe).
* **f\_same\_filesize\_different\_name** - do any files share a filesize but have different names? This can be used to detect backdoors or tools used in multiple staging directories with different names.
