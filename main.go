package main

import (
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	ldap "github.com/go-ldap/ldap/v3"
)

const probeIterval = 10 * time.Second

var searchBaseDn = "DC=example,DC=com"
var searchFilter = "(&(objectclass=*))"
var searchAttributes = []string{"dn", "cn"}

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	bindUser, bindUserDefined := os.LookupEnv("BIND_USER")
	if !bindUserDefined || bindUser == "" {
		log.Fatal("BIND_USER variable is undefined or is empty")
	}

	bindPassword, bindPasswordDefined := os.LookupEnv("BIND_PASSWORD")
	if !bindPasswordDefined || bindPassword == "" {
		log.Fatal("BIND_PASSWORD variable is undefined or is empty")
	}

	ldapAddr, ldapAddrDefined := os.LookupEnv("LDAP_ADDR")
	if !ldapAddrDefined || ldapAddr == "" {
		log.Fatal("LDAP_ADDR variable is undefined or is empty")
	}

	ldapPort, ldapPortDefined := os.LookupEnv("LDAP_PORT")
	if !ldapPortDefined || ldapPort == "" {
		log.Fatal("LDAP_PORT variable is undefined or is empty")
	}

	ldapUrl := "ldap://" + ldapAddr + ":" + ldapPort
	recordMetrics(ldapUrl, bindUser, bindPassword)
	//
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)

}

func recordMetrics(ldapUrl, bindUser, bindPassword string) {

	go func() {
		for {
			connTimeDuration, bindLdapDuration, searchTimeDuration := probeLdap(ldapUrl, bindUser, bindPassword)
			connDuration.Set(connTimeDuration)
			bindDuration.Set(bindLdapDuration)
			searchDuration.Set(searchTimeDuration)
			time.Sleep(probeIterval)
		}
	}()
}

var (
	connDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ldap_connection_delay",
		Help: "LDAP connection delay milliseconds",
	})
	bindDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ldap_bind_delay",
		Help: "LDAP bind delay milliseconds",
	})
	searchDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ldap_search_delay",
		Help: "LDAP search request delay milliseconds",
	})
)

func probeLdap(ldapUrl, bindUser, bindPassword string) (float64, float64, float64) {
	startConnTime := time.Now()
	l, err := ldap.DialURL(ldapUrl)
	if err != nil {
		log.Fatalf("Connection failure: %v\n", err)
	}
	connTimeDuration := float64(time.Since(startConnTime).Milliseconds())
	log.Infof("Connect duration: %v", connTimeDuration)

	defer l.Close()

	startBindTime := time.Now()

	err = l.Bind(bindUser, bindPassword)
	if err != nil {
		log.Fatalf("Bind failure: %v\n", err)
	}

	bindLdapDuration := float64(time.Since(startBindTime).Milliseconds())
	log.Infof("Bind duration: %v", bindLdapDuration)

	searchRequest := ldap.NewSearchRequest(
		searchBaseDn, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,     // The filter to apply
		searchAttributes, // A list attributes to retrieve
		nil,
	)

	startSearchTime := time.Now()
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatalf("Search failure: %v\n", err)
	}

	searchTimeDuration := float64(time.Since(startSearchTime).Milliseconds())
	log.Infof("Search duration: %v", searchTimeDuration)
	for _, entry := range sr.Entries {
		log.Infof("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}

	return connTimeDuration, bindLdapDuration, searchTimeDuration
}
