package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	defaultenv "github.com/caitlinelfring/go-env-default"
	ldap "github.com/go-ldap/ldap/v3"
)

const probeIterval = 10 * time.Second

//var searchAttributes = []string{"dn", "cn"}

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

	searchBaseDn, searchBaseDnDefined := os.LookupEnv("BASE_DN")
	if !searchBaseDnDefined || searchBaseDn == "" {
		log.Fatal("BASE_DN variable is undefined or is empty")
	}

	ldapPort := defaultenv.GetDefault("LDAP_PORT", "389")
	searchFilter := defaultenv.GetDefault("SEARCH_FILTER", "(&(objectclass=*))")
	attributesList := defaultenv.GetDefault("SEARCH_ATTRIBUTES", "cn dn")
	searchAttributes := parseAttributesList(attributesList)
	log.Infof("Search_Attributes is: %v", searchAttributes)

	ldapUrl := "ldap://" + ldapAddr + ":" + ldapPort

	recordMetrics(ldapUrl, bindUser, bindPassword, searchBaseDn, searchFilter, searchAttributes)
	//
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)

}

func parseAttributesList(attributesList string) []string {
	res := make([]string, 0)
	// Trim spaces
	aList := strings.Trim(attributesList, " ")
	for {
		if strings.Contains(aList, " ") {
			spaceIndex := strings.Index(aList, " ")
			attribute := aList[:spaceIndex]
			res = append(res, attribute)
			aList = aList[spaceIndex+1:]
			aList = strings.Trim(aList, " ")
		} else {
			attribute := aList
			res = append(res, attribute)
			break
		}
	}
	return res
}

func recordMetrics(ldapUrl, bindUser, bindPassword, searchBaseDn, searchFilter string,
	searchAttributes []string) {

	go func() {
		for {
			connTimeDuration, bindLdapDuration, searchTimeDuration := probeLdap(ldapUrl,
				bindUser, bindPassword, searchBaseDn, searchFilter, searchAttributes)
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

func probeLdap(ldapUrl, bindUser, bindPassword, searchBaseDn, searchFilter string,
	searchAttributes []string) (float64, float64, float64) {

	startConnTime := time.Now()

	l, err := ldap.DialURL(ldapUrl)
	if err != nil {
		log.Errorf("Connection failure: %v\n", err)
	}
	connTimeDuration := float64(time.Since(startConnTime).Milliseconds())
	log.Infof("Connect duration: %v", connTimeDuration)

	defer l.Close()

	startBindTime := time.Now()

	err = l.Bind(bindUser, bindPassword)
	if err != nil {
		log.Errorf("Bind failure: %v\n", err)
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
		log.Errorf("Search failure: %v\n", err)
	}

	searchTimeDuration := float64(time.Since(startSearchTime).Milliseconds())
	log.Infof("Search duration: %v", searchTimeDuration)
	for _, entry := range sr.Entries {
		log.Infof("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}

	return connTimeDuration, bindLdapDuration, searchTimeDuration
}
