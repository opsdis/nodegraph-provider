URL_NODES="http://localhost:9393/api/nodes/micro"
URL_EDGES="http://localhost:9393/api/edges/micro"
HEADER="Content-Type: application/json"
# Create nodes
curl -s -i -H $HEADER -X POST $URL_NODES -d '{"id": "lb-1",       "title": "lb",         "subTitle": "instance:#01", "detail__role": "load", "arc__failed": 0, "arc__passed": 0, "mainStat": 0, "secondaryStat": 0, "arc__passed":1}'
curl -s -i -H $HEADER -X POST $URL_NODES -d '{"id": "cust-svc-1", "title": "cust-svc-1", "subTitle": "instance:#01", "detail__role": "load", "arc__failed": 0, "arc__passed": 0, "mainStat": 0, "secondaryStat": 0, "arc__passed":1}'
curl -s -i -H $HEADER -X POST $URL_NODES -d '{"id": "cust-svc-2", "title": "cust-svc-2", "subTitle": "instance:#02", "detail__role": "load", "arc__failed": 0, "arc__passed": 0, "mainStat": 0, "secondaryStat": 0, "arc__passed":1}'
curl -s -i -H $HEADER -X POST $URL_NODES -d '{"id": "pay-svc-1",  "title": "pay-svc-1",  "subTitle": "instance:#01", "detail__role": "load", "arc__failed": 0, "arc__passed": 0, "mainStat": 0, "secondaryStat": 0, "arc__passed":1}'
curl -s -i -H $HEADER -X POST $URL_NODES -d '{"id": "book-svc-1", "title": "book-svc-1", "subTitle": "instance:#01", "detail__role": "load", "arc__failed": 0, "arc__passed": 0, "mainStat": 0, "secondaryStat": 0, "arc__passed":1}'

# Create edges
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "lb-1",       "target": "cust-svc-1", "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "lb-1",       "target": "cust-svc-2", "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "cust-svc-1", "target": "pay-svc-1",  "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "cust-svc-1", "target": "book-svc-1", "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "cust-svc-2", "target": "pay-svc-1",  "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "cust-svc-2", "target": "book-svc-1", "mainStat": 0, "secondaryStat": 0}'
curl -s -i -H $HEADER -X POST $URL_EDGES -d '{"source": "pay-svc-1",  "target": "book-svc-1", "mainStat": 0, "secondaryStat": 0}'