// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Copyright 2022 Anders Håål

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang/gddo/httputil/header"
	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	rg "github.com/redislabs/redisgraph-go"
	"github.com/segmentio/ksuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	length     int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.length += n
	return n, err
}

var version = "undefined"

func main() {

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", ExporterName)
		fmt.Printf("Version %s\n", version)
		flag.PrintDefaults()
	}

	SetDefaultValues()

	flag.Int("p", viper.GetInt("port"), "The port to start on")
	logFile := flag.String("logfile", viper.GetString("logfile"), "Set log file, default stdout")
	logFormat := flag.String("logformat", viper.GetString("logformat"), "Set log format to text or json, default json")

	config := flag.String("config", viper.GetString("config"), "Set configuration file, default config.yaml")
	usage := flag.Bool("u", false, "Show usage")
	writeConfig := flag.Bool("default", false, "Write default config")

	flag.Parse()

	log.SetFormatter(&log.JSONFormatter{})
	if *logFormat == "text" {
		log.SetFormatter(&log.TextFormatter{})
	}

	viper.SetConfigName(*config) // name of config file (without extension)
	viper.SetConfigType("yaml")  // REQUIRED if the config file does not have the extension in the name

	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.nodegraph-provider")
	viper.AddConfigPath("/usr/local/etc/nodegraph-provider")
	viper.AddConfigPath("/etc/nodegraph-provider")

	if *usage {
		flag.Usage()
		os.Exit(0)
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		log.SetOutput(f)
	}

	if *writeConfig {
		err := viper.WriteConfigAs("./nodeprovider_default_config.yaml")
		if err != nil {
			log.Error("Can not write default config file - ", err)
		}
		os.Exit(0)
	}

	// Find and read the config file
	err := viper.ReadInConfig()
	if err != nil {
		log.Error("Configuration file not valid - ", err)
		os.Exit(1)
	}

	// Read the graph schema
	var graphs = map[string]map[string][]interface{}{}
	err = viper.UnmarshalKey("graph_schemas", &graphs)
	if err != nil {
		log.Error("Unable to decode node and edge fields into struct - ", err)
		os.Exit(1)
	}

	// Get all fields as map used for validation
	var nodeFields = make(map[string]map[string]string)
	var edgeFields = make(map[string]map[string]string)
	for graphName, graph := range graphs {
		nodes := make(map[string]string)
		for _, fieldInterface := range graph["node_fields"] {
			field := Field{}
			err = mapstructure.Decode(fieldInterface, &field)
			if err != nil {
				log.Error("Unable parse node fields into struct - ", err)
				os.Exit(1)
			}
			nodes[field.FieldName] = field.Type
		}
		nodeFields[graphName] = nodes

		edges := make(map[string]string)
		for _, fieldInterface := range graph["edge_fields"] {
			field := Field{}
			err = mapstructure.Decode(fieldInterface, &field)
			if err != nil {
				log.Error("Unable parse node fields into struct - ", err)
				os.Exit(1)
			}
			edges[field.FieldName] = field.Type
		}
		edgeFields[graphName] = edges
	}

	// Read the redis connection configuration
	var redisConnection = RedisConnection{}
	redisConnection.Host = viper.GetString("redis.host")
	redisConnection.Port = viper.GetString("redis.port")
	redisConnection.DB = viper.GetString("redis.db")
	redisConnection.MaxActive = viper.GetInt("redis.max_active")
	redisConnection.MaxIdle = viper.GetInt("redis.max_idle")

	var pool *redis.Pool

	// Redis connection pool
	pool = &redis.Pool{
		MaxIdle:   redisConnection.MaxIdle,
		MaxActive: redisConnection.MaxActive,
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", fmt.Sprintf("%s:%s", redisConnection.Host, redisConnection.Port))
			if err != nil {
				log.Printf("ERROR: fail init redis pool: %s", err.Error())
				os.Exit(1)
			}
			return conn, err
		},
	}

	allConfig := AllConfig{
		AllGraphs:       graphs,
		NodeFields:      nodeFields,
		EdgeFields:      edgeFields,
		RedisConnection: redisConnection,
		RedisPool:       pool,
	}

	handler := &HandlerInit{allConfig}

	// Create a Prometheus histogram for response time of the exporter
	responseTime := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    MetricsPrefix + "request_duration_seconds",
		Help:    "Histogram of the time (in seconds) each request took to complete.",
		Buckets: []float64{0.050, 0.100, 0.200, 0.500, 0.800, 1.00, 2.000, 3.000},
	},
		[]string{"url", "method", "status"},
	)

	promHandler := &PrometheusInit{responseTime}

	// Setup handler for routes
	setupRoutes(handler, promHandler)

	log.Info(fmt.Sprintf("%s starting on port %d", ExporterName, viper.GetInt("port")))
	log.Info(fmt.Sprintf("connecting to redis at %s:%s on db %s using pool max active %v and max idle %v", redisConnection.Host, redisConnection.Port, redisConnection.DB, redisConnection.MaxActive, redisConnection.MaxIdle))
	s := &http.Server{
		ReadTimeout:  viper.GetDuration("httpserver.read_timeout") * time.Second,
		WriteTimeout: viper.GetDuration("httpserver.write_timeout") * time.Second,
		Addr:         ":" + strconv.Itoa(viper.GetInt("port")),
	}
	log.Fatal(s.ListenAndServe())
}

func setupRoutes(handler *HandlerInit, promHandler *PrometheusInit) {

	rtr := mux.NewRouter()

	// Route handlers for Node Graph API Datasource Plugin
	// the graph path must be part of the data source url like http://localhost:9393/micro
	// where micro is the redis key to the graph model
	rtr.HandleFunc("/{graph:.+}/api/graph/data", handler.getData).Methods("GET")
	rtr.HandleFunc("/{graph:.+}/api/graph/fields", handler.getFields).Methods("GET")
	rtr.HandleFunc("/{graph:.+}/api/health", handler.getHealth).Methods("GET")

	// Routes to the create and update of nodes and edges
	// Node
	rtr.HandleFunc("/api/nodes/{graph:.+}", handler.nodes).Methods("POST")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("PUT")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("DELETE")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("GET")

	// Edge
	rtr.HandleFunc("/api/edges/{graph:.+}", handler.edges).Methods("POST")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("PUT")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("DELETE")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("GET")

	// Graph
	rtr.HandleFunc("/api/graphs/{graph:.+}", handler.createGraph).Methods("POST")
	rtr.HandleFunc("/api/graphs/{graph:.+}", handler.deleteGraph).Methods("DELETE")

	rtr.Use(logcall)
	rtr.Use(promHandler.promMonitor)
	http.Handle("/", rtr)

	// Setup handler for exporter metrics
	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))
}

type HandlerInit struct {
	AllConfig AllConfig
}

func (h HandlerInit) deleteGraph(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	// Get the name of the graph model
	name := params["graph"]

	conn := h.AllConfig.RedisPool.Get()
	defer conn.Close()

	// Check if the graph key exists, if not return 404
	exists, _ := conn.Do("DEL", name)
	if exists == int64(0) {
		sendStatus(w, fmt.Sprintf("No data exists for graph %s", name), http.StatusNotFound)
		return
	}
}

func (h HandlerInit) createGraph(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	// Get the graphName of the graph model
	graphName := params["graph"]

	decoder := json.NewDecoder(r.Body)
	bodyJsonMap := make(map[string][]interface{})
	err := decoder.Decode(&bodyJsonMap)
	if err != nil {
		log.WithFields(log.Fields{
			"object":    "graph",
			"graph":     graphName,
			"requestid": r.Context().Value("requestid"),
			"error":     "Not a valid json",
		}).Warn("Create failed")

		sendStatus(w, fmt.Sprintf("Not a valid json: %v", err), http.StatusBadRequest)
		return
	}

	// Check if nodes and edges is in the body
	_, ok := bodyJsonMap["nodes"]
	if !ok {
		sendStatus(w, fmt.Sprintf("No nodes in the json"), http.StatusBadRequest)
		return
	}
	_, ok = bodyJsonMap["edges"]
	if !ok {
		sendStatus(w, fmt.Sprintf("No edges in the json"), http.StatusBadRequest)
		return
	}

	var nodes []*rg.Node

	// Map the name of the node to the Node
	var nodesMap = make(map[interface{}]*rg.Node)

	// Validate fields
	for _, nodeData := range bodyJsonMap["nodes"] {
		switch value := nodeData.(type) {
		case map[string]interface{}:
			node := rg.Node{Label: "Node", Properties: value}
			nodes = append(nodes, &node)
			nodesMap[value["id"]] = &node
		default:
			sendStatus(w, fmt.Sprintf("Nodes are not correct format"), http.StatusBadRequest)
			return
		}
	}

	var edges []*rg.Edge

	for _, edgeData := range bodyJsonMap["edges"] {
		switch value := edgeData.(type) {
		case map[string]interface{}:
			_, ok := value["source"]
			if !ok {
				sendStatus(w, fmt.Sprintf("Create edge failed, missing source"), http.StatusBadRequest)
				return
			}

			_, ok = value["target"]
			if !ok {
				sendStatus(w, fmt.Sprintf("Create edge failed, missing target"), http.StatusBadRequest)
				return
			}

			properties := make(map[string]interface{})
			for k, v := range value {
				if k != "target" && k != "source" {
					properties[k] = v
				}
			}

			source := nodesMap[value["source"]]
			target := nodesMap[value["target"]]
			edge := rg.Edge{Source: source, Destination: target, Relation: "Edge", Properties: properties}
			edges = append(edges, &edge)
		default:
			sendStatus(w, fmt.Sprintf("Edge are not correct format"), http.StatusBadRequest)
			return
		}
	}

	conn := h.AllConfig.RedisPool.Get()
	defer conn.Close()

	graph := rg.GraphNew(graphName, conn)
	err = graph.Delete()
	if err != nil {
		log.WithFields(log.Fields{
			"object":    "graph",
			"graph":     graphName,
			"requestid": r.Context().Value("requestid"),
			"error":     err,
		}).Info("Delete graph - not exists")
	}

	for _, node := range nodes {
		graph.AddNode(node)
	}

	for _, edge := range edges {
		err := graph.AddEdge(edge)
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "graph",
				"graph":     graphName,
				"requestid": r.Context().Value("requestid"),
				"error":     err,
			}).Error("Add edge failed")
			sendStatus(w, fmt.Sprintf("Add edge failed %s - %v", graphName, err), http.StatusServiceUnavailable)
			return
		}
	}

	graph.Commit()

	/*
		According to the Commit method error should be returned but not
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "graph",
				"graph":     graphName,
				"requestid": r.Context().Value("requestid"),
				"error":     err,
			}).Error("Commit nodes and edges failed")
			sendStatus(w, fmt.Sprintf("Commit nodes and edges failed %s - %v", graphName, err), http.StatusServiceUnavailable)
			return
		}
	*/

	log.WithFields(log.Fields{
		"object":    "graph",
		"graph":     graphName,
		"requestid": r.Context().Value("requestid"),
	}).Info("Created graph")

	sendStatus(w, fmt.Sprintf("Create graph %s", graphName), http.StatusCreated)
	return
}

// getFields returns the fields name and data type for nodes and edges.
// The returned data is in the format according to the nodegraph-api datasource
// https://github.com/hoptical/nodegraph-api-plugin#fetch-graph-fields
func (h HandlerInit) getFields(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	params := mux.Vars(r)
	name := params["graph"]

	var nodeFields []interface{}

	for _, fields := range h.AllConfig.AllGraphs[name]["node_fields"] {
		values := fields.(map[interface{}]interface{})
		nodeField := map[string]interface{}{}
		for k, v := range values {
			nodeField[k.(string)] = v
		}

		nodeFields = append(nodeFields, nodeField)
	}

	var edgeFields []interface{}
	for _, fields := range h.AllConfig.AllGraphs[name]["edge_fields"] {
		values := fields.(map[interface{}]interface{})
		edgeField := map[string]interface{}{}
		for k, v := range values {
			edgeField[k.(string)] = v
		}

		edgeFields = append(edgeFields, edgeField)
	}

	response := make(map[string]interface{})
	response["edges_fields"] = edgeFields
	response["nodes_fields"] = nodeFields
	bodyText, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(bodyText)

	return
}

// getData return the nodes and edges based on the WHERE clause in the query parameter.
// The returned data is in the format according to the nodegraph-api datasource
// https://github.com/hoptical/nodegraph-api-plugin#fetch-graph-data

// The query parameter must be a valid chyper WHERE clause expression, e.g.
// query=source.title+%3D+%27bookinfo%2Fproductpage%27+and+rel.mainStat+%3E+1
// The query expression should not include WHERE and must be url encoded.
// If the query parameter is not set all nodes and edges in the graph is returned.
// Source nodes must be named source, target nodes must be named target and edges must
// be named edge.
func (h HandlerInit) getData(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	params := mux.Vars(r)
	// Get the name of the graph model
	name := params["graph"]

	whereClause := ""
	whereQuery, ok := r.URL.Query()["query"]
	if ok && len(whereQuery) == 1 && len(whereQuery[0]) > 0 {
		whereClause = fmt.Sprintf("WHERE %s", whereQuery[0])
	}

	conn := h.AllConfig.RedisPool.Get()
	defer conn.Close()

	// Check if the graph key exists, if not return 404
	exists, _ := conn.Do("EXISTS", name)
	if exists == int64(0) {
		sendStatus(w, fmt.Sprintf("No data exists for graph %s", name), http.StatusNotFound)
		return
	}

	graph := rg.GraphNew(name, conn)

	// Get edges
	query := fmt.Sprintf("Match (source:Node)-[edge:Edge]->(target:Node) %s Return source,edge,target", whereClause)
	result, err := graph.Query(query)
	//result.PrettyPrint()
	if err != nil {
		log.WithFields(log.Fields{
			"object":    "edges",
			"requestid": r.Context().Value("requestid"),
			"error":     err,
		}).Error("Get edges")

		sendStatus(w, fmt.Sprintf("Get edge data failed %v", err), http.StatusInternalServerError)
		return
	}

	//result.PrettyPrint()
	var edges []interface{}
	nodesMap := make(map[interface{}]interface{})

	for result.Next() { // Next returns true until the iterator is depleted.
		edge := make(map[string]interface{})
		res := result.Record()

		// Get source node
		source := res.GetByIndex(0).(*rg.Node)
		if _, ok := nodesMap[source.GetProperty("id")]; !ok {
			node := make(map[string]interface{})
			for key, value := range source.Properties {
				// Add check that correct to field
				node[key] = value
			}
			nodesMap[source.GetProperty("id")] = node
		}

		// Get target
		target := res.GetByIndex(2).(*rg.Node)
		if _, ok := nodesMap[target.GetProperty("id")]; !ok {
			node := make(map[string]interface{})
			for key, value := range target.Properties {
				// Add check that correct to field
				node[key] = value
			}
			nodesMap[target.GetProperty("id")] = node
		}

		// Get edge

		edgeData := res.GetByIndex(1).(*rg.Edge)
		for key, value := range edgeData.Properties {
			edge[key] = value
		}
		edge["source"] = source.GetProperty("id")
		edge["target"] = target.GetProperty("id")

		edge["id"] = fmt.Sprintf("%s:%s", source.GetProperty("id"), target.GetProperty("id"))

		edges = append(edges, edge)
	}

	// Process the find nodes
	var nodes []interface{}
	for _, value := range nodesMap {
		nodes = append(nodes, value)
	}

	response := make(map[string]interface{})
	response["edges"] = edges

	response["nodes"] = nodes

	bodyText, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(bodyText)

	return
}

// getHealth is used by the data source to verify connection
func (h HandlerInit) getHealth(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	params := mux.Vars(r)
	name := params["graph"]

	bodyText := fmt.Sprintf("API is working well! Using graph %s\n", name)
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(bodyText))

	return
}

// nodes manage POST, PUT, DELETE and GET for node objects
func (h HandlerInit) nodes(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)
	// Get the name of the graph model
	name := params["graph"]

	if h.validateHeader(w, r) {
		return
	}

	conn := h.AllConfig.RedisPool.Get()
	defer conn.Close()

	graph := rg.GraphNew(name, conn)

	// POST node
	if r.Method == http.MethodPost {
		properties, done := h.validateJsonBody(w, r, h.AllConfig.NodeFields, name)
		if done {
			return
		}

		query := fmt.Sprintf("MATCH (n:Node {id: '%s'}) RETURN n", properties["id"])
		result, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "node",
				"requestid": r.Context().Value("requestid"),
				"nodeid":    properties["id"],
				"error":     err,
			}).Error("Failed to check if node exist")

			sendStatus(w, fmt.Sprintf("Failed to create node %s", properties["id"]), http.StatusInternalServerError)
			return
		}

		if result.Empty() {

			node := rg.Node{Label: "Node", Properties: properties}

			graph.AddNode(&node)

			_, err := graph.Commit()

			if err != nil {
				log.WithFields(log.Fields{
					"object":    "node",
					"requestid": r.Context().Value("requestid"),
					"nodeid":    properties["id"],
					"error":     err,
				}).Error("Failed to create node")

				sendStatus(w, fmt.Sprintf("Failed to create node %s", properties["id"]), http.StatusInternalServerError)
				return
			}

			log.WithFields(log.Fields{
				"object":    "node",
				"requestid": r.Context().Value("requestid"),
				"nodeid":    properties["id"],
			}).Info("Create")

			sendStatus(w, fmt.Sprintf("Create node id %s", properties["id"]), http.StatusCreated)
			return
		} else {
			log.WithFields(log.Fields{
				"object":    "node",
				"requestid": r.Context().Value("requestid"),
				"nodeid":    properties["id"],
			}).Info("Create - already exists")

			sendStatus(w, fmt.Sprintf("Node with id %s already exists", properties["id"]), http.StatusConflict)
			return
		}
	}

	// Check if the node exists
	if r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodGet {
		id := params["id"]
		query := fmt.Sprintf("MATCH (n:Node {id: '%s'}) RETURN n", id)
		result, err := graph.Query(query)
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "node",
				"requestid": r.Context().Value("requestid"),
				"id":        id,
				"error":     err,
			}).Error("Check if node exists")

			sendStatus(w, fmt.Sprintf("Check if node exist failed for %s", id), http.StatusInternalServerError)
			return
		}

		if result.Empty() {
			sendStatus(w, fmt.Sprintf("Node id %s does not exists", id), http.StatusNotFound)
			return
		}
	}

	// Read the path parameters
	id := params["id"]

	// GET node
	if r.Method == http.MethodGet {
		query := fmt.Sprintf("MATCH (n:Node {id: '%s'}) RETURN n", id)
		result, err := graph.Query(query)
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"id":        id,
				"error":     err,
			}).Error("Delete")

			sendStatus(w, fmt.Sprintf("Get failed for %s", id), http.StatusInternalServerError)
			return
		}

		var resp = rg.Node{}
		for result.Next() {
			record := result.Record()
			resp = *(record.Values()[0]).(*rg.Node)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp.Properties)
		return
	}

	// PUT node
	if r.Method == http.MethodPut {
		values := r.URL.Query()

		for k := range values {
			if _, ok := h.AllConfig.NodeFields[name][k]; !ok {
				sendStatus(w, fmt.Sprintf("Create node failed, %s is no a valid property", k), http.StatusBadRequest)
				return
			}
		}

		nodeProperties := make([]string, 0, len(values))
		for k, v := range values {
			nodeProperties = append(nodeProperties, fmt.Sprintf("n.%s = %v", k, v[0]))
		}

		properties := fmt.Sprintf("%s", strings.Join(nodeProperties, ","))

		query := fmt.Sprintf("MATCH (n:Node {id: '%s'}) SET %s RETURN n", id, properties)
		_, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"id":        id,
				"error":     err,
			}).Error("Update")

			sendStatus(w, fmt.Sprintf("Update failed for %s", id), http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"object":     "node",
			"requestid":  r.Context().Value("requestid"),
			"nodeid":     id,
			"properties": properties,
		}).Info("Update")

		sendStatus(w, fmt.Sprintf("Update node id %s", id), http.StatusOK)
		return
	}

	// DELETE node
	if r.Method == http.MethodDelete {
		query := fmt.Sprintf("MATCH (n:Node {id: '%s'}) DELETE n", id)
		_, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"id":        id,
				"error":     err,
			}).Error("Delete")

			sendStatus(w, fmt.Sprintf("Delete failed for %s", id), http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"object":    "node",
			"requestid": r.Context().Value("requestid"),
			"nodeid":    id,
		}).Info("Delete")

		sendStatus(w, fmt.Sprintf("Delete node id %s", id), http.StatusOK)
		return
	}

}

// edges manage POST, PUT, DELETE and GET for node objects
func (h HandlerInit) edges(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)
	// Get the name of the graph model
	name := params["graph"]

	if h.validateHeader(w, r) {
		return
	}

	conn := h.AllConfig.RedisPool.Get()
	defer conn.Close()

	graph := rg.GraphNew(name, conn)

	// POST edge
	if r.Method == http.MethodPost {
		bodyJsonMap, done := h.validateJsonBody(w, r, h.AllConfig.EdgeFields, name)
		if done {
			return
		}

		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' RETURN n,r,m",
			bodyJsonMap["source"], bodyJsonMap["target"])
		result, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  bodyJsonMap["source"],
				"targetid":  bodyJsonMap["target"],
				"error":     err,
			}).Error("Failed to check is edge exist")

			sendStatus(w, fmt.Sprintf("Create failed between source id %s and target id %s", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusInternalServerError)
			return
		}

		if result.Empty() {
			edgeProperties := make([]string, 0, len(bodyJsonMap)-2)
			for k, v := range bodyJsonMap {
				if k != "source" && k != "target" {
					// Exclude source_id and target_id
					edgeProperties = append(edgeProperties, fmt.Sprintf("%s:%v", k, v))
				}
			}
			properties := fmt.Sprintf("{%s}", strings.Join(edgeProperties, ","))

			query := fmt.Sprintf("MATCH (a:Node),(b:Node) WHERE a.id = '%s' AND b.id = '%s' CREATE (a)-[r:Edge %s]->(b) RETURN r",
				bodyJsonMap["source"], bodyJsonMap["target"], properties)

			result, err := graph.Query(query)
			//result.PrettyPrint()

			if err != nil {
				log.WithFields(log.Fields{
					"object":    "edge",
					"requestid": r.Context().Value("requestid"),
					"sourceid":  bodyJsonMap["source"],
					"targetid":  bodyJsonMap["target"],
					"error":     err,
				}).Error("Failed to create edge")

				sendStatus(w, fmt.Sprintf("Create edge failed between source id %s and target id %s", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusInternalServerError)
				return
			}
			if result.Empty() {
				sendStatus(w, fmt.Sprintf("Create edge failed between source id %s and target id %s since some node(s) do not exists", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusBadRequest)
				return
			}
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  bodyJsonMap["source"],
				"targetid":  bodyJsonMap["target"],
			}).Info("Create")

			sendStatus(w, fmt.Sprintf("Create edge sourceid %s and target %s", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusCreated)
			return

		} else {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  bodyJsonMap["source_id"],
				"targetid":  bodyJsonMap["target_id"],
			}).Info("Create - already exists")

			sendStatus(w, fmt.Sprintf("Edge between source id %s and target id %s already exists", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusConflict)
			return
		}
	}

	// Check if the edge exists
	if r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodGet {
		sourceId := params["source_id"]
		targetId := params["target_id"]

		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' RETURN r",
			sourceId, targetId)
		result, err := graph.Query(query)

		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"error":     err,
			}).Error("Check if edge exists")

			sendStatus(w, fmt.Sprintf("Check if edge exist failed"), http.StatusInternalServerError)
			return
		}

		//result.PrettyPrint()
		if result.Empty() {
			sendStatus(w, fmt.Sprintf("Edge between source id %s and target id %s does not exists", sourceId, targetId), http.StatusNotFound)
			return
		}
	}

	// Read the path parameters
	sourceId := params["source_id"]
	targetId := params["target_id"]

	// GET edge
	if r.Method == http.MethodGet {
		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' RETURN r", sourceId, targetId)
		result, err := graph.Query(query)
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  sourceId,
				"targetid":  targetId,
				"error":     err,
			}).Error("Update")

			sendStatus(w, fmt.Sprintf("Update failed between source id %s and target id %s", sourceId, targetId), http.StatusInternalServerError)
			return
		}

		var resp = rg.Edge{}
		for result.Next() {
			record := result.Record()
			resp = *(record.Values()[0]).(*rg.Edge)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp.Properties)
		return
	}

	// PUT edge
	if r.Method == http.MethodPut {
		values := r.URL.Query()

		for k := range values {
			if _, ok := h.AllConfig.EdgeFields[name][k]; !ok {
				sendStatus(w, fmt.Sprintf("Create edge failed, %s is no a valid property", k), http.StatusBadRequest)
				return
			}
		}

		edgeProperties := make([]string, 0, len(values))
		for k, v := range values {
			edgeProperties = append(edgeProperties, fmt.Sprintf("r.%s = %v", k, v[0]))
		}

		properties := fmt.Sprintf("%s", strings.Join(edgeProperties, ","))

		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' SET %s RETURN r",
			sourceId, targetId, properties)
		_, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  sourceId,
				"targetid":  targetId,
				"error":     err,
			}).Error("Update")

			sendStatus(w, fmt.Sprintf("Update failed between source id %s and target id %s", sourceId, targetId), http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"object":     "edge",
			"requestid":  r.Context().Value("requestid"),
			"sourceid":   sourceId,
			"targetid":   targetId,
			"properties": properties,
		}).Info("Update")

		sendStatus(w, fmt.Sprintf("Update edge between source id %s and target id %s", sourceId, targetId), http.StatusOK)
		return
	}

	// DELETE edge
	if r.Method == http.MethodDelete {
		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' DELETE r",
			sourceId, targetId)
		_, err := graph.Query(query)
		//result.PrettyPrint()
		if err != nil {
			log.WithFields(log.Fields{
				"object":    "edge",
				"requestid": r.Context().Value("requestid"),
				"sourceid":  sourceId,
				"targetid":  targetId,
				"error":     err,
			}).Error("Delete")

			sendStatus(w, fmt.Sprintf("Delete failed between source id %s and target id %s", sourceId, targetId), http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"object":    "edge",
			"requestid": r.Context().Value("requestid"),
			"sourceid":  sourceId,
			"targetid":  targetId,
		}).Info("Delete")

		sendStatus(w, fmt.Sprintf("Delete edge between source id %s and target id %s", sourceId, targetId), http.StatusOK)
		return
	}
}

// sendStatus send http response and status
func sendStatus(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf("{\"message\": \"%s\"}\n", message)))
}

// validateJsonBody validate that the request body is a json and validate that only graph schema fields are present
func (h HandlerInit) validateJsonBody(w http.ResponseWriter, r *http.Request, fields map[string]map[string]string,
	name string) (map[string]interface{}, bool) {
	decoder := json.NewDecoder(r.Body)
	bodyJsonMap := make(map[string]interface{})
	err := decoder.Decode(&bodyJsonMap)
	if err != nil {

		log.WithFields(log.Fields{
			"object":    "node",
			"requestid": r.Context().Value("requestid"),
			"error":     "Not a valid json",
		}).Warn("Create failed")

		sendStatus(w, fmt.Sprintf("Create failed: %v", err), http.StatusBadRequest)
		return nil, true
	}

	for k := range bodyJsonMap {
		if _, ok := fields[name][k]; !ok {
			sendStatus(w, fmt.Sprintf("Create failed %s is no a valid property\n", k), http.StatusBadRequest)
			return nil, true
		}
	}
	return bodyJsonMap, false
}

// validateHeader validate that Content-Type is application/json
func (h HandlerInit) validateHeader(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			sendStatus(w, fmt.Sprintf("Content-Type header is not application/json"), http.StatusUnsupportedMediaType)
			return true
		}
	}
	return false
}

func nextRequestID() ksuid.KSUID {
	return ksuid.New()
}

func logcall(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()

		lrw := loggingResponseWriter{ResponseWriter: w}
		requestid := nextRequestID()

		ctx := context.WithValue(r.Context(), "requestid", requestid)
		next.ServeHTTP(&lrw, r.WithContext(ctx)) // call original

		w.Header().Set("Content-Length", strconv.Itoa(lrw.length))
		log.WithFields(log.Fields{
			"method":    r.Method,
			"uri":       r.RequestURI,
			"status":    lrw.statusCode,
			"length":    lrw.length,
			"requestid": requestid,
			"exec_time": time.Since(start).Microseconds(),
		}).Info("api call")
	})

}

type PrometheusInit struct {
	responseTime *prometheus.HistogramVec
}

func (h PrometheusInit) promMonitor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()

		lrw := loggingResponseWriter{ResponseWriter: w}

		next.ServeHTTP(&lrw, r) // call original

		response := time.Since(start).Seconds()

		h.responseTime.With(prometheus.Labels{"url": r.URL.Path, "method": r.Method, "status": strconv.Itoa(lrw.statusCode)}).Observe(response)
	})
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
