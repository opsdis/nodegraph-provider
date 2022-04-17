![Docker Pulls](https://img.shields.io/docker/pulls/athenodon/nodegraph-provider)

nodegraph-provider
----------------

# Overview
The nodegraph-provider works with the Grafana datasource "Node Graph API Datasource Plugin", 
https://github.com/exaco/nodegraph-api-plugin.

The nodegraph-provider use a RedisGraph, https://github.com/RedisGraph/RedisGraph, to keep a graph model 
of what to expose to the Node Graph API datasource. 

To create a model the nodegraph-provider expose api endpoints to create and update nodes and edges. 
The attributes that can be used is limited to the attributes of the Grafana Node Graph panel plugin, 
https://grafana.com/docs/grafana/latest/visualizations/node-graph/.

![Overview](docs/nodegraph-provider.png?raw=true "Overview")

# Configuration
For available configuration check out the `config.yaml`. All configuration can be overridden by environment variables 
except the `graph_schemas`.

Prefix all configuration varaibles with `NODEGRAPH_PROVIDER_` and replace `.` with `_`, e.g. set the redis server:

    export NODEGRAPH_PROVIDER_REDIS_HOST=my_redis_host
    

# Graph schema model

The graph model must be compatible to the data model for nodes and edges in the Node Graph panel. 
The attributes allowed is specified at https://grafana.com/docs/grafana/latest/visualizations/node-graph/#data-api.

In the nodegraph-provider each instance schema of a model is described in the configuration file, e.g.

```yaml
graph_schemas:
  micro:
    node_fields:
      - field_name: "id"
        type: "string"
      - field_name: "title"
        type: "string"
      - field_name: "subTitle"
        type: "string"
      - field_name: "mainStat"
        type: "string"
        displayName: "CPU"
      - field_name: "secondaryStat"
        type: "number"
      - field_name: "arc__failed"
        type: "number"
        color: "red"
      - field_name: "arc__passed"
        type: "number"
        color: "green"
      - field_name: "detail__role"
        type: "string"
        displayName: "Role"
    edge_fields:
      - field_name: "id"
        type: "string"
      - field_name: "source"
        type: "string"
      - field_name: "target"
        type: "string"
      - field_name: "mainStat"
        type: "number"
      - field_name: "secondaryStat"
        type: "number"
      - field_name: "detail__traffic"
        type: "string"
```

The `graph_schemas` can have multiple named schema definitions. Above is a schema called `micro`.
The name is used as a key in all API accesses to support multiple instances. E.g. when setting up the URL in the
Node Graph API Datasource Plugin we define it as part of the path, `http://localhost:9393/micro`.
This enables nodegraph-provider to support multiple data sources in a single instance.
The schema defines the different fields and the type, string or number, that are allowed for the specific schema. 
  

# API endpoints

All endpoint expects the header "Content-Type" set to "application/json"

## Data source API
   
    GET /{graph_schema}/api/graph/data
	GET /{graph_schema}/api/graph/fields
	GET /{graph_schema}/api/health


## Mange nodes and edges

	POST /api/nodes/{graph_schema}
	GET /api/nodes/{graph_schema}/{id}
	PUT /api/nodes/{graph_schema}/{id}
	DELETE /api/nodes/{graph_schema}/{id}
	
	POST /api/edges/{graph_schema} 
	GET /api/edges/{graph_schema}/{source_id}/{target_id}
	PUT /api/edges/{graph_schema}/{source_id}/{target_id}
	DELETE /api/edges/{graph_schema}/{source_id}/{target_id}

POST operations expect a json body. The content should only include the field names in the graph schema.

Node example:

```json
{
  "id": "lb-01",
  "title": "lb01",
  "subTitle": "instance:#01",   
  "arc__failed": 0.0,
  "arc__passed": 0.0,
  "detail__role": "load",
  "mainStat": 0.0,
  "secondaryStat": 0.0
}
```

PUT takes query parameters with the fields to be updated and id as a path parameter.

DELETE and GET do not have any query parameters. 


```bash
curl -s -i  -H "Content-Type: application/json" -X PUT "localhost:9393/api/nodes/micro/lb-01?arc__failed=0.1?arc__passed=0.9"
```

## Manage a complete graph
The api endpoints will operate on a complete graph. The POST will first
delete before create. For a client that have the full "picture" of the graph
model, this is the most effective endpoint to use.

    POST /api/graphs/{graph_schema}
    DELETE /api/graphs/{graph_schema}

> The graph endpoints in singulars are deprecated:
> 
>  POST /api/graphs/{graph_schema}
> 
>  DELETE /api/graphs/{graph_schema}

The POST endpoint requiere a body of a list of nodes and edges, e.g.
```json
{
  "nodes": [
    {
      "id": "lb-1",
      "title": "lb",
      "subTitle": "instance:#01",
      "detail__role": "load",
      "arc__failed": 0,
      "arc__passed": 1,
      "mainStat": 0,
      "secondaryStat": 0
    },
    ....
    
  ],
  "edges": [
    {
      "source": "lb-1",
      "target": "cust-svc-1",
      "mainStat": 0,
      "secondaryStat": 0
    },
    ....
  ]
}
```

Please see the `examples/graph.json` and `examples/setup_graph.sh` for a
complete example.

## Deprecated API	
The following api are deprecated: 

    POST /api/controller/{graph_schema}/delete-all





## Return status

- 200
  - Successful - PUT, DELETE, GET
- 201
 - Create successful - POST
- 400 
  - Not a valid json - POST
  - Not a valid field name - POST, PUT
- 404
  - Object do not exist - PUT, DELETE, GET
- 409 
  - Object already exists - POST
- 415
  - Invalid value for header "Content-Type"


# Get started
Install Grafana and datasource https://github.com/exaco/nodegraph-api-plugin.
Start grafana to allow unsigned plugins

    export GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=hamedkarbasi93-nodegraphapi-datasource ; ./bin/grafana-serve

Start redis with module RedisGraph. Simple way just use docker.

    docker run -p 6379:6379 redislabs/redismod
    
Start nodegraph-provider

    go build -o build/nodegraph-provider  *.go
    ./build/nodegraph-provider
    
To see all options 

    ./build/nodegraph-provider -h


Create a data source in Grafana with the nodegraph-api-plugin and set url to `http://localhost:9393/micro`.
Name it to `Micro`.

Create a dashboard and select the "Node Graph" plugin. Select the data source `Micro`.
 
Load the simple graph model by create nodes and edges:

    ./examples/setup_test.sh
    
Or run the example to create a complete graph:

    ./examples/setup_graph.sh

In Grafana you should now see this.
![Initial Graph](docs/graph_1.png?raw=true "Start graph")

Add a new node with id `cust-svc-2`

    curl -s -i  -H "Content-Type: application/json" -X POST localhost:9393/api/nodes/micro -d @examples/node_create.json

Create an edge between `lb-1` and `cust-svc-3` 

    curl -s -i  -H "Content-Type: application/json" -X POST localhost:9393/api/edges/micro -d @examples/edge_create.json 

Update metrics on `lb-1`

    curl -s -i  -H "Content-Type: application/json" -X PUT "localhost:9393/api/nodes/micro/book-svc-1?mainStat=$RANDOM&secondaryStat=$RANDOM&arc__failed=0.1&arc__passed=0.9"

Update metrics on edge between `lb-1` to `cust-svc-1
    
    curl -s -i  -H "Content-Type: application/json" -X PUT "localhost:9393/api/edges/micro/lb-1/cust-svc-1?mainStat=$RANDOM&secondaryStat=$RANDOM"

You should now see something like this.
![Updated Graph](docs/graph_2.png?raw=true "Updated graph")

# Build docker 
Use the Dockerfile in the root directory of the project

     docker build --tag nodegraph-provider .
     
To run the image a config file must be mounted
    
     docker run -p 9393:9393 -v $(pwd)/config_tempo.yaml:/app/config.yaml nodegraph-provider
    
Environment variables can be set to override defaults and config file

     docker run -p 9393:9393 -v $(pwd)/config_tempo.yaml:/app/config.yaml -e NODEGRAPH_PROVIDER_PORT=9393 -e NODEGRAPH_PROVIDER_REDIS_HOST=localhost -e NODEGRAPH_PROVIDER_REDIS_PORT=6379  nodegraph-provider 

# Demo examples
Checkout the [tempo_trace_aggregation](https://github.com/opsdis/tempo_trace_aggregation) project
where nodegraph-provider is used to create a "dynamic service map" based on
aggregated traces stored in [Grafana Tempo](https://github.com/grafana/tempo).




