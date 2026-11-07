package main

import (
 "encoding/base64"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func authRequest(h http.Handler,method,path,authorization,origin,ctype string)*httptest.ResponseRecorder{
 r:=httptest.NewRequest(method,path,strings.NewReader("{}"))
 r.RemoteAddr="192.0.2.51:51515"
 r.Host="panel.example.com"
 if authorization!=""{r.Header.Set("Authorization",authorization)}
 if origin!=""{r.Header.Set("Origin",origin)}
 if ctype!=""{r.Header.Set("Content-Type",ctype)}
 w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w
}
func TestPublicBrowserPasswordAuthentication(t *testing.T){
 t.Setenv("ADMIN_TOKEN","api-token")
 t.Setenv("ADMIN_USERNAME","operator")
 t.Setenv("ADMIN_PASSWORD","very-strong-test-password")
 t.Setenv("LINODE_TOKEN","")
 s:=testServer(http.DefaultClient)
 h:=newHandler(s)
 basic:=func(u,p string)string{return "Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p))}
 for _,p:=range []string{"/","/api/health","/api/instances","/api/wp2/nodes","/api/monitor","/api/deployments/unknown"}{
  w:=authRequest(h,"GET",p,"","","")
  want:=401;if p=="/"{want=302}
  if w.Code!=want{t.Errorf("%s unauthenticated HTTP %d",p,w.Code)}
  if p=="/"&&w.Header().Get("Location")!="/login"{t.Error("missing browser login redirect")}
 }
 if w:=authRequest(h,"GET","/api/health",basic("operator","very-strong-test-password"),"","");w.Code!=200{t.Fatalf("valid browser login HTTP %d %s",w.Code,w.Body.String())}
 if w:=authRequest(h,"GET","/",basic("operator","very-strong-test-password"),"","");w.Code!=200||!strings.Contains(w.Body.String(),"Linode 节点管理"){t.Fatalf("panel HTML inaccessible after login: %d",w.Code)}
 if w:=authRequest(h,"GET","/api/health","Bearer api-token","","");w.Code!=200{t.Fatalf("legacy bearer authorization failed: %d",w.Code)}
 for _,a:=range []string{basic("operator","wrong-password"),basic("wrong","very-strong-test-password")}{
  if w:=authRequest(h,"GET","/api/health",a,"","");w.Code!=401{t.Errorf("wrong login HTTP %d",w.Code)}
 }
}
func TestBrowserPOSTOriginProtection(t *testing.T){
 t.Setenv("ADMIN_USERNAME","operator")
 t.Setenv("ADMIN_PASSWORD","very-strong-test-password")
 t.Setenv("ADMIN_TOKEN","api-token")
 s:=testServer(http.DefaultClient);h:=newHandler(s)
 auth:="Basic "+base64.StdEncoding.EncodeToString([]byte("operator:very-strong-test-password"))
 for _,tc:=range []struct{origin,ctype string;want int}{
  {"https://evil.example","application/json",403},
  {"http://panel.example.com","application/json",403},
  {"https://panel.example.com","text/plain",415},
  {"https://panel.example.com","application/json",400},
 }{
  got:=authRequest(h,"POST","/api/instances/0/reboot",auth,tc.origin,tc.ctype)
  if got.Code!=tc.want{t.Errorf("origin=%q type=%q expected=%d got=%d body=%s",tc.origin,tc.ctype,tc.want,got.Code,got.Body.String())}
 }
}
func TestRepeatedLoginFailuresDoNotLockOut(t *testing.T){
 t.Setenv("ADMIN_USERNAME","operator")
 t.Setenv("ADMIN_PASSWORD","very-strong-test-password")
 t.Setenv("ADMIN_TOKEN","api-token")
 h:=newHandler(testServer(http.DefaultClient))
 wrong:="Basic "+base64.StdEncoding.EncodeToString([]byte("operator:invalid-password"))
 for i:=0;i<20;i++{if w:=authRequest(h,"GET","/api/health",wrong,"","");w.Code!=401{t.Fatalf("attempt %d: %d",i,w.Code)}}
 good:="Basic "+base64.StdEncoding.EncodeToString([]byte("operator:very-strong-test-password"))
 if w:=authRequest(h,"GET","/api/health",good,"","");w.Code!=200||w.Header().Get("Retry-After")!=""{t.Fatalf("valid login after repeated failures expected 200, got %d",w.Code)}
}
func TestValidateAdminConfig(t *testing.T){
 for _,tc:=range []struct{name,user,password,token string;valid bool}{
  {"short browser password","admin","123456789","api-token",false},
  {"missing browser password","admin","","api-token",false},
  {"missing username","","long-enough-password","",false},
  {"no credentials","","","",false},
  {"browser login","admin","123456789012","",true},
  {"API only","","","api-token",true},
 }{
  t.Run(tc.name,func(t *testing.T){
   t.Setenv("ADMIN_USERNAME",tc.user)
   t.Setenv("ADMIN_PASSWORD",tc.password)
   t.Setenv("ADMIN_TOKEN",tc.token)
   if err:=validateAdminConfig();(err==nil)!=tc.valid{t.Fatalf("valid=%v, error=%v",tc.valid,err)}
  })
 }
}
