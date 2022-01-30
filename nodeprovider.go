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
// Copyright 2020 Opsdis AB

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/mux"
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
	viper.AddConfigPath("$HOME/.aci-exporter")
	viper.AddConfigPath("/usr/local/etc/aci-exporter")
	viper.AddConfigPath("/etc/aci-exporter")

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


	/*
	var nodes = Nodes{}
	err = viper.UnmarshalKey("nodes", &nodes)
	if err != nil {

		log.Error("Unable to decode nodes into struct - ", err)
		os.Exit(1)
	}
	*/

	//var nodeFields = NodeFields{}
	var nodeFields = []interface{}{}
	err = viper.UnmarshalKey("node_fields", &nodeFields)
	if err != nil {

		log.Error("Unable to decode node fields into struct - ", err)
		os.Exit(1)
	}

	//var nodeFields = NodeFields{}
	var edgeFields = []interface{}{}
	err = viper.UnmarshalKey("edge_fields", &edgeFields)
	if err != nil {

		log.Error("Unable to decode node fields into struct - ", err)
		os.Exit(1)
	}
	allConfig := AllConfig{
		AllEdgeFields: edgeFields,
		AllNodeFields: nodeFields,
	}

	handler := &HandlerInit{allConfig}
	//	handler := &HandlerInit{allQueries}

	// Create a Prometheus histogram for response time of the exporter
	responseTime := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    MetricsPrefix + "request_duration_seconds",
		Help:    "Histogram of the time (in seconds) each request took to complete.",
		Buckets: []float64{0.050, 0.100, 0.200, 0.500, 0.800, 1.00, 2.000, 3.000},
	},
		[]string{"url", "method", "status"},
	)

	promHandler := &PromethusInit{responseTime}

	// Setup handler for aci destinations
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
	//rtr.HandleFunc("/{graph:.+}/api/graph/data", handler.getData).Methods("GET")
	rtr.HandleFunc("/{graph:.+}/api/graph/data", handler.getData).Methods("GET")
	rtr.HandleFunc("/{graph:.+}/api/graph/fields", handler.getFields).Methods("GET")
	rtr.HandleFunc("/{graph:.+}/api/health", handler.getData).Methods("GET")
	rtr.Use(logcall)
	rtr.Use(promHandler.promMonitor)
	http.Handle("/", rtr)

	/*
	http.Handle("/Xapi/graph/data", logcall(promMonitor(http.HandlerFunc(handler.getData), responseTime,
		"/api/graph/data")))
	http.Handle("/Xapi/graph/fields", logcall(promMonitor(http.HandlerFunc(handler.getFields), responseTime,
		"/api/graph/fields")))
	http.Handle("/Xapi/health", logcall(promMonitor(http.HandlerFunc(handler.getHealth), responseTime,
		"/api/health")))
	http.Handle("/Xalive", logcall(promMonitor(http.HandlerFunc(alive), responseTime,
		"/alive")))
	*/

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

type PromethusInit struct {
	responseTime *prometheus.HistogramVec
}

func (h HandlerInit) getFields(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Printf("%", r.URL)
	params := mux.Vars(r)
	name := params["graph"]
	fmt.Printf("Graph: %", name)

	nodeFields := []interface{}{}

	for _, fields := range h.AllConfig.AllNodeFields {
		values := fields.(map[interface{}]interface{})
		nodeField := map[string]interface{}{}
		for k, v := range values {
			nodeField[k.(string)] = v
		}

		nodeFields = append(nodeFields, nodeField)
	}

	edgeFields := []interface{}{}
	for _, fields := range h.AllConfig.AllEdgeFields {
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
	w.Write([]byte(bodyText))

	return
}

func (h HandlerInit) getData(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	fmt.Printf("%", r.URL)
	params := mux.Vars(r)
	name := params["graph"]
	fmt.Printf("Graph: %", name)


	conn, _ := redis.Dial("tcp", "127.0.0.1:6379")
	defer conn.Close()

	graph := rg.GraphNew(name, conn)
	query := "Match (n:Node)-[r:Edge]->(m:Node) Return n.id,r,m.id"

	// result is a QueryResult struct containing the query's generated records and statistics.
	result, _ := graph.Query(query)
	result.PrettyPrint()

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
		edge["mainStat"] = edgeData.Properties["mainStat"]

		target := r.GetByIndex(2)
		edge["target"] = target

		count = count + 1

		edges = append(edges, edge)
	}

	// Get nodes
	query = "Match (n:Node) Return n"

	result, _ = graph.Query(query)
	result.PrettyPrint()

	// create a dynamic id for edges
	//count = 0
	nodes := []interface{}{}
	for result.Next() {
		node := make(map[string]interface{})
		r := result.Record()
		nodeData := r.GetByIndex(0).(*rg.Node)
		for key, value := range nodeData.Properties {
			// Add check that correct to field

			node[key] = value
		}
/*
		node["id"] = nodeData.Properties["id"]
		node["title"] = nodeData.Properties["title"]
		node["subTitle"] = nodeData.Properties["subTitle"]
		node["mainStat"] = nodeData.Properties["mainStat"]
		node["secondaryStat"] = nodeData.Properties["secondaryStat"]
*/

		nodes = append(nodes, node)
	}

	response := make(map[string]interface{})
	response["edges"] = edges
	response["nodes"] = nodes

	bodyText, _ := json.Marshal(response)
	//bodyText := "Get fields"
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(bodyText))

	return
}


func (h HandlerInit) getHealth(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	fmt.Printf("%", r.URL)
	params := mux.Vars(r)
	name := params["graph"]
	fmt.Printf("Graph: %", name)

	bodyText := "API is working well!"
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(bodyText))

	return
}
func alive(w http.ResponseWriter, r *http.Request) {

	var alive = fmt.Sprintf("Alive!\n")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(alive)))
	lrw := loggingResponseWriter{ResponseWriter: w}
	lrw.WriteHeader(200)

	w.Write([]byte(alive))
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
			"fabric":    r.URL.Query().Get("target"),
			"status":    lrw.statusCode,
			"length":    lrw.length,
			"requestid": requestid,
			"exec_time": time.Since(start).Microseconds(),
		}).Info("api call")
	})

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