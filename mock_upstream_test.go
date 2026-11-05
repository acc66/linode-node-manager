package main

import (
 "net/http"
 "net/http/httptest"
 "os"
)

// Normal runs exercise HTTP/TLS. Restricted environments can explicitly use an
// in-memory transport to verify the same handlers without opening sockets.
type mockUpstream struct {
 URL string
 client *http.Client
 close func()
}
func (s *mockUpstream) Client()*http.Client{return s.client}
func (s *mockUpstream) Close(){if s.close!=nil{s.close()}}
type handlerTransport struct{handler http.Handler}
func (t handlerTransport) RoundTrip(r *http.Request)(*http.Response,error){
 if err:=r.Context().Err();err!=nil{return nil,err}
 if r.Body!=nil{defer r.Body.Close()}
 w:=httptest.NewRecorder()
 // Populate RequestURI as a real HTTP server would.
 request:=r.Clone(r.Context());request.RequestURI=r.URL.RequestURI()
 t.handler.ServeHTTP(w,request)
 response:=w.Result();response.Request=r
 return response,nil
}
func newMockUpstream(handler http.Handler)*mockUpstream{
 if os.Getenv("LINODE_TEST_IN_MEMORY")=="1"{
  return &mockUpstream{URL:"https://mock.invalid",client:&http.Client{Transport:handlerTransport{handler:handler}}}
 }
 server:=httptest.NewTLSServer(handler)
 return &mockUpstream{URL:server.URL,client:server.Client(),close:server.Close}
}
