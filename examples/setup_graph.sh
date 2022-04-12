URL_BATCH="http://localhost:9393/api/graph/micro"
HEADER="Content-Type: application/json"
# Create nodes
curl -s -i -H $HEADER -X POST $URL_BATCH -d @examples/graph.json
