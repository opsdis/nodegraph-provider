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


# Graph schema model

The graph model must be compatible to the data model for nodes and edges in the Node Graph panel. 
The attributes allowed is specified at https://grafana.com/docs/grafana/latest/visualizations/node-graph/#data-api.

In the nodegraph-provider each instance schema of a model are described in the configuration file, e.g.

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
This enables nodegraph-provider to support multiple datasources in a single instance.
The schema defines the different fields and the type, string or number, that are allowd for the specific schema. 
  

# API endpoints

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
	
All endpoint expects the header "Content-Type" set to "application/json"

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

PUT takes query parameters with the fields to be updated.

```bash
curl -s -i  -H "Content-Type: application/json" -X PUT "localhost:9393/api/nodes/micro/lb-01?arc__failed=0.1?arc__passed=0.9"
```
    
> PUT should maybe be renamed to PATCH.

### Return status
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


