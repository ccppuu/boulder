package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/golang/protobuf/proto"
	gsb_proto "github.com/letsencrypt/boulder/test/gsb-test-srv/proto"
)

type testSrv struct {
	apiKey string
	hp     hashPrefixes
}

const (
	protoMime           = "application/x-protobuf"
	minHashPrefixLength = 4
	maxHashPrefixLength = sha256.Size
)

// An empty threat list update response for padding responses out
var emptyThreatListUpdateResp = &gsb_proto.FetchThreatListUpdatesResponse_ListUpdateResponse{
	ThreatType:      gsb_proto.ThreatType_MALWARE,
	PlatformType:    gsb_proto.PlatformType_ANY_PLATFORM,
	ThreatEntryType: gsb_proto.ThreatEntryType_URL,
	ResponseType:    gsb_proto.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE,
	/*
	 * This is the SHA1Sum of `[]byte{}`, e.g. an empty update
	 */
	Checksum: &gsb_proto.Checksum{
		Sha256: []byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
			0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
	},
}

func unmarshal(req *http.Request, pbReq proto.Message) error {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(body, pbReq); err != nil {
		return err
	}
	return nil
}

func marshal(resp http.ResponseWriter, pbResp proto.Message) error {
	resp.Header().Set("Content-Type", protoMime)
	body, err := proto.Marshal(pbResp)
	if err != nil {
		return err
	}
	if _, err := resp.Write(body); err != nil {
		return err
	}
	return nil
}

type hashPrefix struct {
	hash string
	url  string
}

func newHashPrefix(pattern string) hashPrefix {
	hash := sha256.New()
	hash.Write([]byte(pattern))
	return hashPrefix{
		hash: string(hash.Sum(nil)),
		url:  pattern,
	}
}

type hashPrefixes []hashPrefix

func (p hashPrefixes) SHA256() []byte {
	hash := sha256.New()
	for _, hp := range p {
		hash.Write([]byte(hp.hash))
	}
	return hash.Sum(nil)
}

func (p hashPrefixes) bytes() []byte {
	var hashes []byte
	for _, h := range p {
		hashes = append(hashes, []byte(h.hash)...)
	}
	return hashes
}

func (p hashPrefixes) Len() int           { return len(p) }
func (p hashPrefixes) Less(i, j int) bool { return p[i].hash < p[j].hash }
func (p hashPrefixes) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (p hashPrefixes) sort() { sort.Sort(p) }

func (p hashPrefixes) searchWith(f func(int) bool) *hashPrefix {
	i := sort.Search(len(p), f)
	if i > 0 && i < len(p) {
		return &p[i]
	}
	return nil
}

func (p hashPrefixes) findByURL(url string) *hashPrefix {
	return p.searchWith(func(i int) bool {
		return p[i].url == url
	})
}

func (p hashPrefixes) findByHash(h string) *hashPrefix {
	return p.searchWith(func(i int) bool {
		return p[i].hash == h
	})
}

func (t *testSrv) dbUpdateResponse() *gsb_proto.FetchThreatListUpdatesResponse {
	updateResp := &gsb_proto.FetchThreatListUpdatesResponse{}

	// A response to add some bad URLs
	addResponse := &gsb_proto.FetchThreatListUpdatesResponse_ListUpdateResponse{
		ThreatType:      gsb_proto.ThreatType_MALWARE,
		PlatformType:    gsb_proto.PlatformType_ANY_PLATFORM,
		ThreatEntryType: gsb_proto.ThreatEntryType_URL,
		ResponseType:    gsb_proto.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE,
		Additions: []*gsb_proto.ThreatEntrySet{
			&gsb_proto.ThreatEntrySet{},
		},
	}

	additions := []*gsb_proto.ThreatEntrySet{
		&gsb_proto.ThreatEntrySet{
			CompressionType: gsb_proto.CompressionType_RAW,
			RawHashes: &gsb_proto.RawHashes{
				PrefixSize: maxHashPrefixLength,
			},
		},
	}

	hashes := t.hp.bytes()
	additions[0].RawHashes.RawHashes = hashes
	addResponse.Additions = additions
	addResponse.Checksum = &gsb_proto.Checksum{Sha256: t.hp.SHA256()}

	// The `sblookup` client is hardcoded to expect exactly three list update
	// responses, one for each of the threat types it cares about.
	// We send two empty updates and one to add full hashes for the hardcoded
	// sites. Its important to send these in the order empty, empty, non-empty
	// because each update squashes the previous' contents (Unclear why)
	updateResp.ListUpdateResponses = []*gsb_proto.FetchThreatListUpdatesResponse_ListUpdateResponse{
		emptyThreatListUpdateResp,
		emptyThreatListUpdateResp,
		addResponse,
	}

	return updateResp
}

func (t *testSrv) threatListUpdateFetch(w http.ResponseWriter, r *http.Request) {
	updateReq := &gsb_proto.FetchThreatListUpdatesRequest{}
	err := unmarshal(r, updateReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updateResp := t.dbUpdateResponse()
	fmt.Printf("Sending resp: %#v\n", updateResp)

	err = marshal(w, updateResp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("processed: %#v\n", updateReq)
}

func (t *testSrv) fullHashesFind(w http.ResponseWriter, r *http.Request) {
	findReq := &gsb_proto.FindFullHashesRequest{}
	err := unmarshal(r, findReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if findReq.ThreatInfo == nil || findReq.ThreatInfo.ThreatEntries == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	te := findReq.ThreatInfo.ThreatEntries
	if len(te) < 1 {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	threat := te[0]
	fmt.Printf("ThreatEntries[0]: %#v\n", threat)

	var match *hashPrefix
	if threat.Url != "" {
		match = t.hp.findByURL(string(threat.Url))
	} else {
		match = t.hp.findByHash(string(threat.Hash))
	}

	resp := &gsb_proto.FindFullHashesResponse{
		MinimumWaitDuration: &gsb_proto.Duration{
			Seconds: 1,
		},
		NegativeCacheDuration: &gsb_proto.Duration{
			Seconds: 1,
		},
	}

	if match == nil {
		fmt.Printf("Didn't find %#v\n", threat.Hash)
	} else {
		resp.Matches = []*gsb_proto.ThreatMatch{
			&gsb_proto.ThreatMatch{
				ThreatType:      gsb_proto.ThreatType_MALWARE,
				PlatformType:    gsb_proto.PlatformType_ANY_PLATFORM,
				ThreatEntryType: gsb_proto.ThreatEntryType_URL,
				Threat: &gsb_proto.ThreatEntry{
					Hash: []byte(match.hash),
					Url:  match.url,
				},
				CacheDuration: &gsb_proto.Duration{
					Seconds: 1,
				},
			},
		}
	}

	err = marshal(w, resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (t *testSrv) processRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("processRequesT() Path: %#v\n", r.URL.Path)

	// We only process POST methods
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	// And only for specific paths
	if r.URL.Path != "/v4/threatListUpdates:fetch" && r.URL.Path != "/v4/fullHashes:find" {
	}
	// And only for protobuf Content-Type
	if r.Header.Get("Content-Type") != protoMime {
		w.WriteHeader(405)
		return
	}
	// We require the client sends the correct key
	// TODO(@cpu): Send back a protocol-correct bad auth response
	key := r.URL.Query().Get("key")
	if key != t.apiKey {
		w.WriteHeader(405)
		return
	}

	switch r.URL.Path {
	case "/v4/threatListUpdates:fetch":
		t.threatListUpdateFetch(w, r)
		return
	case "/v4/fullHashes:find":
		t.fullHashesFind(w, r)
		return
	}

	http.NotFound(w, r)
	return
}

func (t *testSrv) start(listenAddr string) {
	handler := http.HandlerFunc(t.processRequest)
	go func() {
		err := http.ListenAndServe(listenAddr, handler)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			return
		}
	}()
}

func newTestServer(apiKey string, unsafeURLs []string) testSrv {
	ts := testSrv{
		apiKey: apiKey,
	}

	var hp hashPrefixes
	for _, s := range unsafeURLs {
		if !strings.HasSuffix(s, "/") {
			s = s + "/"
		}

		hp = append(hp, newHashPrefix(s))
	}
	hp.sort()
	ts.hp = hp

	return ts
}

func main() {
	key := flag.String("apikey", "", "API key for client access")
	listen := flag.String("listenAddress", ":6000", "Listen address for HTTP server")

	flag.Parse()

	if *key == "" {
		fmt.Fprintf(os.Stderr, "Error: -apikey must not be empty\n")
		os.Exit(1)
	}

	fmt.Printf("Starting GSB Test Server on %q\n", *listen)

	ts := newTestServer(*key, []string{"evil.com", "malware.biz"})
	ts.start(*listen)

	// Block on an empty channel
	forever := make(chan bool, 1)
	<-forever
}
