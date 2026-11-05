package main

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestAuth(t *testing.T) {
 t.Setenv("ADMIN_TOKEN","test-admin-token")
 s:=&Server{}
 h:=s.auth(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusNoContent)})
 for _,tt:=range []struct{name,header string;want int}{
  {"missing","",401},
  {"wrong","Bearer wrong",401},
  {"valid","Bearer test-admin-token",204},
 }{
  t.Run(tt.name,func(t *testing.T){
   r:=httptest.NewRequest("GET","/api/health",nil)
   if tt.header!=""{r.Header.Set("Authorization",tt.header)}
   w:=httptest.NewRecorder();h(w,r)
   if w.Code!=tt.want{t.Fatalf("got %d want %d",w.Code,tt.want)}
  })
 }
}
func TestShellQuote(t *testing.T){
 v:=shellQuote("foo'bar")
 if v!="'foo'\\''bar'"{t.Fatalf("unexpected quoted string: %q",v)}
}
func TestPublicIP(t *testing.T){
 cases:=[]struct{ips []string;want string}{
  {[]string{"10.0.0.1","8.8.8.8"},"8.8.8.8"},
  {[]string{"127.0.0.1","192.168.1.1"},""},
 }
 for _,c:=range cases{if got:=publicIP(Instance{IPv4:c.ips});got!=c.want{t.Errorf("got %q want %q",got,c.want)}}
}
func TestWP2InvalidConfiguration(t *testing.T){
 t.Setenv("WP2_BASE_URL","http://insecure.example")
 t.Setenv("WP2_API_TOKEN","test-token")
 s:=&Server{client:http.DefaultClient}
 w:=httptest.NewRecorder()
 s.wpNodes(w,httptest.NewRequest("GET","/api/wp2/nodes",nil))
 if w.Code!=503||!strings.Contains(w.Body.String(),"HTTPS"){t.Fatalf("got %d: %s",w.Code,w.Body.String())}
}
