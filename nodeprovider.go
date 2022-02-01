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

// Implement interface WriteHeader
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
	err = viper.UnmarshalKey("redis", &redisConnection)
	if err != nil {
		log.Error("Unable to decode redis connection struct - ", err)
		os.Exit(1)
	}

	allConfig := AllConfig{
		AllGraphs:       graphs,
		NodeFields:      nodeFields,
		EdgeFields:      edgeFields,
		RedisConnection: redisConnection,
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

	promHandler := &PromethusInit{responseTime}

	// Setup handler for routes
	setupRoutes(handler, promHandler)

	log.Info(fmt.Sprintf("%s starting on port %d", ExporterName, viper.GetInt("port")))
	log.Info(fmt.Sprintf("Read timeout %s, Write timeout %s", viper.GetDuration("httpserver.read_timeout")*time.Second, viper.GetDuration("httpserver.write_timeout")*time.Second))
	s := &http.Server{
		ReadTimeout:  viper.GetDuration("httpserver.read_timeout") * time.Second,
		WriteTimeout: viper.GetDuration("httpserver.write_timeout") * time.Second,
		Addr:         ":" + strconv.Itoa(viper.GetInt("port")),
	}
	log.Fatal(s.ListenAndServe())
}

func setupRoutes(handler *HandlerInit, promHandler *PromethusInit) {

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
	//rtr.HandleFunc("/api/nodes/{graph:.+}", handler.nodes).Methods("GET")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("PUT")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("DELETE")
	rtr.HandleFunc("/api/nodes/{graph:.+}/{id:.+}", handler.nodes).Methods("GET")

	// Edge
	rtr.HandleFunc("/api/edges/{graph:.+}", handler.edges).Methods("POST")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("PUT")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("DELETE")
	rtr.HandleFunc("/api/edges/{graph:.+}/{source_id:.+}/{target_id:.+}", handler.edges).Methods("GET")
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

func (h HandlerInit) getData(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	params := mux.Vars(r)
	// Get the name of the graph model
	name := params["graph"]

	conn, err := h.getRedisConnection()
	if err != nil {
		sendStatus(w, "Failed to connect to db", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	graph := rg.GraphNew(name, conn)
	query := "Match (n:Node)-[r:Edge]->(m:Node) Return n.id,r,m.id"

	// result is a QueryResult struct containing the query's generated records and statistics.
	result, err := graph.Query(query)
	//result.PrettyPrint()
	if err != nil {
		log.WithFields(log.Fields{
			"object":    "edges",
			"requestid": r.Context().Value("requestid"),
			"error":     err,
		}).Error("Get edges")

		sendStatus(w, fmt.Sprintf("Get edge data failed"), http.StatusInternalServerError)
		return
	}

	// create a dynamic id for edges
	count := 0
	var edges []interface{}
	for result.Next() { // Next returns true until the iterator is depleted.
		edge := make(map[string]interface{})
		r := result.Record()

		edge["id"] = count

		source := r.GetByIndex(0)
		edge["source"] = source

		edgeData := r.GetByIndex(1).(*rg.Edge)
		for key, value := range edgeData.Properties {
			edge[key] = value
		}

		//edge["mainStat"] = edgeData.Properties["mainStat"]

		target := r.GetByIndex(2)
		edge["target"] = target

		count = count + 1

		edges = append(edges, edge)
	}

	// Get nodes
	query = "Match (n:Node) Return n"

	result, err = graph.Query(query)
	//result.PrettyPrint()
	if err != nil {
		log.WithFields(log.Fields{
			"object":    "nodes",
			"requestid": r.Context().Value("requestid"),
			"error":     err,
		}).Error("Get nodes")

		sendStatus(w, fmt.Sprintf("Get node data failed"), http.StatusInternalServerError)
		return
	}

	var nodes []interface{}
	for result.Next() {
		node := make(map[string]interface{})
		r := result.Record()
		nodeData := r.GetByIndex(0).(*rg.Node)

		for key, value := range nodeData.Properties {
			// Add check that correct to field

			node[key] = value
		}

		nodes = append(nodes, node)
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

	conn, err := h.getRedisConnection()
	if err != nil {
		sendStatus(w, "Failed to connect to db", http.StatusServiceUnavailable)
		return
	}

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
		result, _ := graph.Query(query)

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
			nodeProperties = append(nodeProperties, fmt.Sprintf("n.%s = %v", k, ToString(v[0], h.AllConfig.NodeFields[name][k])))
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
			}).Error("Delete")

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

	conn, err := h.getRedisConnection()
	if err != nil {
		sendStatus(w, "Failed to connect to db", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	graph := rg.GraphNew(name, conn)

	// POST edge
	if r.Method == http.MethodPost {
		bodyJsonMap, done := h.validateJsonBody(w, r, h.AllConfig.EdgeFields, name)
		if done {
			return
		}

		query := fmt.Sprintf("MATCH (n:Node)-[r:Edge]->(m:Node) WHERE n.id = '%s' and m.id = '%s' RETURN r",
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
					edgeProperties = append(edgeProperties, fmt.Sprintf("%s:%v", k, ToString(v, h.AllConfig.EdgeFields[name][k])))
				}
			}
			properties := fmt.Sprintf("{%s}", strings.Join(edgeProperties, ","))

			query := fmt.Sprintf("MATCH (a:Node),(b:Node) WHERE a.id = '%s' AND b.id = '%s' CREATE (a)-[r:Edge %s]->(b) RETURN r",
				bodyJsonMap["source"], bodyJsonMap["target"], properties)

			_, err := graph.Query(query)
			//result.PrettyPrint()
			if err != nil {
				log.WithFields(log.Fields{
					"object":    "edge",
					"requestid": r.Context().Value("requestid"),
					"sourceid":  bodyJsonMap["source"],
					"targetid":  bodyJsonMap["target"],
					"error":     err,
				}).Error("Failed to create edge")

				sendStatus(w, fmt.Sprintf("Create failed between source id %s and target id %s", bodyJsonMap["source"], bodyJsonMap["target"]), http.StatusInternalServerError)
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
		result, _ := graph.Query(query)
		result.PrettyPrint()
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
			edgeProperties = append(edgeProperties, fmt.Sprintf("r.%s = %v", k, ToString(v[0], h.AllConfig.EdgeFields[name][k])))
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

// getRedisConnection return a redis connection
func (h HandlerInit) getRedisConnection() (redis.Conn, error) {
	conn, err := redis.Dial("tcp", fmt.Sprintf("%s:%s", h.AllConfig.RedisConnection.Host, h.AllConfig.RedisConnection.Port))
	if err != nil {
		log.WithFields(log.Fields{
			"object": "db",
			//"requestid": r.Context().Value("requestid"),
			"error": err,
		}).Error("Connect to db")
	}
	return conn, err
}

func ToString(i interface{}, fieldType string) string {
	if i == nil {
		return "null"
	}

	switch fieldType {
	case "string":
		s := i.(string)
		return strconv.Quote(s)
	case "number":
		switch i.(type) {
		case string:
			return i.(string)
		case int:
			return strconv.Itoa(i.(int))
		case float64:
			return strconv.FormatFloat(i.(float64), 'f', -1, 64)

		default:
			return i.(string)
		}
	default:
		return i.(string)
	}
}

// From the RedisGraph code base
func XToString(i interface{}) string {
	if i == nil {
		return "null"
	}

	switch i.(type) {
	case string:
		s := i.(string)
		//return fmt.Sprintf("'%s'", s)
		return strconv.Quote(s)
	case int:
		return strconv.Itoa(i.(int))
	case float64:
		return strconv.FormatFloat(i.(float64), 'f', -1, 64)
	case bool:
		return strconv.FormatBool(i.(bool))
	case []interface{}:
		arr := i.([]interface{})
		return arrayToString(arr)
	default:
		panic("Unrecognized type to convert to string")
	}
}

// From the RedisGraph code base
func arrayToString(arr []interface{}) string {
	var arrayLength = len(arr)
	var strArray []string
	for i := 0; i < arrayLength; i++ {
		strArray = append(strArray, XToString(arr[i]))
	}
	return "[" + strings.Join(strArray, ",") + "]"
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

type PromethusInit struct {
	responseTime *prometheus.HistogramVec
}

func (h PromethusInit) promMonitor(next http.Handler) http.Handler {
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
