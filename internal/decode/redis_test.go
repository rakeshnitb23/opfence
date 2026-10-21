package decode

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestClassifyRedis(t *testing.T) {
	R, W, D, I, A, U, C := classes.Read, classes.Write, classes.Delete, classes.Irreversible, classes.Access, classes.Unknown, classes.Credential
	cases := []struct {
		cmd  string
		want classes.Class
	}{
		// Reads, by the READONLY flag.
		{"GET k", R}, {"get k", R}, {"MGET a b", R}, {"SCAN 0 MATCH user:* COUNT 100", R}, {"TYPE k", R},
		{"TTL k", R}, {"EXISTS k", R}, {"HGETALL h", R}, {"LRANGE l 0 -1", R}, {"ZRANGE z 0 -1", R},
		{"XRANGE s - +", R}, {"DUMP k", R}, {"DBSIZE", R}, {"SORT_RO l", R},
		// Neither flag: transactions, pub/sub, connection state.
		{"MULTI", R}, {"EXEC", R}, {"WATCH k", R}, {"PING", R}, {"SELECT 1", R}, {"SUBSCRIBE c", R},
		{"CLIENT SETNAME x", R}, {"CLIENT LIST", R}, {"COMMAND COUNT", R}, {"CONFIG", R},
		// Writes that add or change.
		{"SET k v", W}, {"SET k v EX 60", W}, {"HSET h f v", W}, {"LPUSH l x", W}, {"INCR n", W},
		{"SADD s m", W}, {"ZADD z 1 m", W}, {"XADD s * f v", W}, {"PERSIST k", W}, {"COPY a b REPLACE", W},
		{"RESTORE k 0 payload", W}, {"PUBLISH c m", W}, {"XREADGROUP GROUP g c STREAMS s >", W},
		{"SCRIPT LOAD return 1", W}, {"SCRIPT FLUSH", W}, {"FUNCTION LOAD code", W}, {"MOVE k 1", W}, {"SWAPDB 0 1", W},
		{"SPUBLISH c m", W},
		// Writes that remove keys or members.
		{"DEL k", D}, {"DEL a b c", D}, {"UNLINK k", D}, {"GETDEL k", D}, {"HDEL h f", D}, {"SREM s m", D},
		{"ZREM z m", D}, {"LREM l 0 x", D}, {"LTRIM l 0 99", D}, {"LPOP l", D}, {"RPOP l 5", D}, {"SPOP s", D},
		{"ZREMRANGEBYSCORE z -inf +inf", D}, {"XTRIM s MAXLEN 0", D}, {"XDEL s 1-1", D},
		{"XGROUP DESTROY s g", D}, {"RENAME a b", D}, {"FUNCTION DELETE lib", D},
		// Whole databases.
		{"FLUSHALL", I}, {"FLUSHALL ASYNC", I}, {"flushdb", I}, {"FUNCTION FLUSH", I},
		// TTLs that delete at once.
		{"EXPIRE k 60", W}, {"EXPIRE k 0", D}, {"EXPIRE k -1", D}, {"EXPIRE k x", D}, {"EXPIRE k", W},
		{"PEXPIRE k 1500", W}, {"PEXPIRE k 0", D}, {"EXPIREAT k 1893456000", D}, {"PEXPIREAT k 1", D},
		{"HEXPIRE h 60 FIELDS 1 f", W}, {"HEXPIRE h 0 FIELDS 1 f", D}, {"HPEXPIREAT h 1 FIELDS 1 f", D},
		// Arguments decide.
		{"SORT l", R}, {"SORT l LIMIT 0 10", R}, {"SORT l STORE dst", W}, {"sort l store dst", W},
		{"HELLO 3", R}, {"HELLO 3 AUTH default p", A},
		// Code, access, secrets, administration.
		{"EVAL return 1 0", U}, {"EVALSHA abc 0", U}, {"EVAL_RO return 1 0", U}, {"FCALL f 0", U}, {"FCALL_RO f 0", U},
		{"SCRIPT KILL", U}, {"MIGRATE host 6379 k 0 5000", U}, {"CONFIG SET maxmemory 1mb", U},
		{"config set appendonly no", U}, {"CONFIG REWRITE", U}, {"CLIENT KILL ID 5", U}, {"CLIENT PAUSE 1000", U},
		{"DEBUG SLEEP 1", U}, {"SHUTDOWN NOSAVE", U}, {"REPLICAOF host 6379", U}, {"MODULE LOAD /tmp/x.so", U},
		{"SAVE", U}, {"BGSAVE", U}, {"CLUSTER RESET", U},
		{"AUTH user pass", A}, {"ACL SETUSER u on >p ~* +@all", A}, {"acl deluser u", A},
		{"ACL LIST", C}, {"ACL GETUSER default", C}, {"CONFIG GET requirepass", C}, {"CONFIG GET *", C}, {"MONITOR", C},
		{"ACL WHOAMI", R}, {"ACL LOG", R}, {"ACL CAT", R}, {"KEYS *", R}, {"INFO", R}, {"SLOWLOG GET", R},
		// RedisJSON, as Upstash documents it.
		{"JSON.GET doc $", R}, {"JSON.MGET a b $", R}, {"JSON.SET doc $ {}", W}, {"JSON.MERGE doc $ {}", W},
		{"JSON.DEL doc $", D}, {"JSON.FORGET doc $.a", D}, {"JSON.CLEAR doc $", D}, {"JSON.ARRPOP doc $.a", D},
		{"json.arrtrim doc $.a 0 1", D}, {"JSON.FROBNICATE doc", U},
		// What Opfence does not know.
		{"FROBNICATE", U}, {"CONFIG FROBNICATE", U}, {"FT.SEARCH idx *", U}, {"", U}, {"   ", U},
	}
	for _, c := range cases {
		cmd := strings.Fields(c.cmd)
		if c.cmd != "" && len(cmd) == 0 {
			cmd = []string{c.cmd}
		}
		if got := ClassifyRedis(cmd); !reflect.DeepEqual(got, []classes.Class{c.want}) {
			t.Errorf("ClassifyRedis(%q) = %v, want %s", c.cmd, got, c.want)
		}
	}
}

// Every command in Valkey's table gets exactly one valid class.
func TestClassifyRedisWholeTable(t *testing.T) {
	if len(redisCommands) < 400 || redisTableSource == "" {
		t.Fatalf("table has %d commands from %q", len(redisCommands), redisTableSource)
	}
	for name := range redisCommands {
		got := ClassifyRedis(strings.Fields(name))
		if len(got) != 1 || !got[0].Valid() {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestRedisCommands(t *testing.T) {
	cases := []struct {
		json string
		want [][]string
		ok   bool
	}{
		{`[["GET","k"]]`, [][]string{{"GET", "k"}}, true},
		{`[["SET","k","v"],["DEL","k"]]`, [][]string{{"SET", "k", "v"}, {"DEL", "k"}}, true},
		{`["SET","k","v"]`, [][]string{{"SET", "k", "v"}}, true},
		{`[["EXPIRE","k",0]]`, [][]string{{"EXPIRE", "k", "0"}}, true},
		{`[]`, nil, true},
		{`[["GET",{"x":1}]]`, nil, false},
		{`[["GET","k"],"DEL"]`, nil, false},
		{`[[["GET"]]]`, nil, false},
		{`"GET k"`, nil, false},
		{`{"cmd":"GET"}`, nil, false},
	}
	for _, c := range cases {
		var v any
		dec := json.NewDecoder(strings.NewReader(c.json))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		got, ok := RedisCommands(v)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("RedisCommands(%s) = %q, %v; want %q, %v", c.json, got, ok, c.want, c.ok)
		}
	}
}

func TestClassifyRedisCommands(t *testing.T) {
	got := ClassifyRedisCommands([][]string{{"GET", "k"}, {"DEL", "k"}, {"GET", "j"}, {"FLUSHDB"}})
	if want := []classes.Class{classes.Read, classes.Delete, classes.Irreversible}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := ClassifyRedisCommands(nil); got != nil {
		t.Fatalf("no commands: got %v", got)
	}
}

func FuzzClassifyRedis(f *testing.F) {
	for _, s := range []string{"GET k", "FLUSHALL", "EXPIRE k 0", "CONFIG GET *", "JSON.DEL d $", "SORT l STORE d", "HELLO 3 AUTH u p"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := ClassifyRedis(strings.Split(s, " "))
		if len(got) != 1 || !got[0].Valid() {
			t.Fatalf("%q: %v", s, got)
		}
	})
}
