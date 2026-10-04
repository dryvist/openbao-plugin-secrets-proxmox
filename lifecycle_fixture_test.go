package proxmox

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pve "github.com/luthermonson/go-proxmox"
)

type lifecycleFixture struct {
	server          *httptest.Server
	mu              sync.Mutex
	secret          string
	users           map[string]*pve.User
	roles           map[string]map[string]bool
	tokens          map[string]map[string]pve.Token
	acl             pve.ACLs
	failMethod      string
	failPath        string
	failCount       int
	echoSecret      bool
	nullTokens      bool
	privsepRejected bool
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	f := &lifecycleFixture{secret: "synthetic-private-management-sentinel", users: map[string]*pve.User{
		"manager@pve": {UserID: "manager@pve", Enable: true}, "reader@pve": {UserID: "reader@pve", Enable: true},
	}, roles: map[string]map[string]bool{"PVEAuditor": {"VM.Audit": true}, "Administrator": {"VM.Audit": true, "Sys.Audit": true}}, tokens: map[string]map[string]pve.Token{}, acl: pve.ACLs{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *lifecycleFixture) configData() map[string]interface{} {
	return map[string]interface{}{"endpoint": f.server.URL, "token_id": "manager@pve!engine", "token_secret": f.secret,
		"ca_cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))}
}

func (f *lifecycleFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "PVEAPIToken=manager@pve!engine="+f.secret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api2/json")
	if f.failCount > 0 && r.Method == f.failMethod && (f.failPath == "" || strings.HasPrefix(path, f.failPath)) {
		f.failCount--
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, f.secret)
		return
	}
	var data interface{}
	switch {
	case path == "/version":
		data = map[string]string{"version": "9.0.3", "release": "9.0"}
	case path == "/access/users":
		switch r.Method {
		case http.MethodGet:
			users := pve.Users{}
			for _, user := range f.users {
				users = append(users, user)
			}
			data = users
		case http.MethodPost:
			var user pve.NewUser
			if err := json.NewDecoder(r.Body).Decode(&user); err != nil || f.users[user.UserID] != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.users[user.UserID] = &pve.User{UserID: user.UserID, Enable: pve.IntOrBool(user.Enable), Comment: user.Comment}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case strings.HasPrefix(path, "/access/users/"):
		parts := strings.Split(strings.TrimPrefix(path, "/access/users/"), "/")
		user := parts[0]
		if f.users[user] == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if len(parts) == 1 {
			if r.Method == http.MethodDelete {
				delete(f.users, user)
				delete(f.tokens, user)
			} else {
				data = f.users[user]
			}
		} else if len(parts) == 2 && parts[1] == "token" {
			if !f.nullTokens {
				tokens := pve.Tokens{}
				for _, token := range f.tokens[user] {
					copy := token
					tokens = append(tokens, &copy)
				}
				data = tokens
			}
		} else if len(parts) == 3 && parts[1] == "token" {
			id := parts[2]
			if user == "manager@pve" && id == "engine" {
				data = pve.Token{TokenID: id, Privsep: true}
			} else {
				switch r.Method {
				case http.MethodPost:
					var token pve.Token
					if err := json.NewDecoder(r.Body).Decode(&token); err != nil || !bool(token.Privsep) {
						f.privsepRejected = true
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if f.tokens[user] == nil {
						f.tokens[user] = map[string]pve.Token{}
					}
					token.TokenID = id
					f.tokens[user][id] = token
					value := "issued-" + id
					if f.echoSecret {
						value = f.secret
					}
					data = pve.NewAPIToken{FullTokenID: user + "!" + id, Value: value, Info: token}
				case http.MethodGet:
					token, ok := f.tokens[user][id]
					if !ok {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					data = token
				case http.MethodPut:
					var token pve.Token
					if err := json.NewDecoder(r.Body).Decode(&token); err != nil || !bool(token.Privsep) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if _, ok := f.tokens[user][id]; !ok {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					token.TokenID = id
					f.tokens[user][id] = token
				case http.MethodDelete:
					if _, ok := f.tokens[user][id]; !ok {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					delete(f.tokens[user], id)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	case path == "/access/roles":
		if r.Method == http.MethodGet {
			roles := pve.Roles{}
			for id := range f.roles {
				roles = append(roles, &pve.Role{RoleID: id})
			}
			data = roles
		} else if r.Method == http.MethodPost {
			var role map[string]string
			if err := json.NewDecoder(r.Body).Decode(&role); err != nil || f.roles[role["roleid"]] != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			privileges := map[string]bool{}
			for _, privilege := range strings.Fields(role["privs"]) {
				privileges[privilege] = true
			}
			f.roles[role["roleid"]] = privileges
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case strings.HasPrefix(path, "/access/roles/"):
		id := strings.TrimPrefix(path, "/access/roles/")
		if f.roles[id] == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.roles, id)
		} else {
			data = f.roles[id]
		}
	case path == "/access/acl":
		if r.Method == http.MethodGet {
			data = f.acl
		} else if r.Method == http.MethodPut {
			var options pve.ACLOptions
			if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			kind, principal := "token", options.Tokens
			if options.Users != "" {
				kind, principal = "user", options.Users
			}
			kept := pve.ACLs{}
			for _, grant := range f.acl {
				if grant.Path != options.Path || grant.RoleID != options.Roles || grant.Type != kind || grant.UGID != principal {
					kept = append(kept, grant)
				}
			}
			if !bool(options.Delete) {
				kept = append(kept, &pve.ACL{Path: options.Path, RoleID: options.Roles, Type: kind, UGID: principal, Propagate: options.Propagate})
			}
			f.acl = kept
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case path == "/access/permissions":
		data = map[string]interface{}{r.URL.Query().Get("path"): map[string]bool{"VM.Audit": true, "Sys.Audit": true}}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
}

func (f *lifecycleFixture) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, tokens := range f.tokens {
		count += len(tokens)
	}
	return count
}
