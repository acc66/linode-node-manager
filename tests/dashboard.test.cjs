const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('main.go','utf8').split('<script>')[1].split('</script>')[0];
const elements={};const el=()=>({value:'',options:[],checked:false,disabled:false,textContent:'',innerHTML:'',replaceChildren(){this.options=[]},appendChild(o){this.options.push(o)},querySelectorAll(){return []},get selectedOptions(){return this.options.filter(o=>o.value===this.value)},showModal(){this.open=true},close(){this.open=false}});
const get=id=>elements[id]??=el();const calls=[];let promptValue=null,connected=false;
const instance={id:5,account_id:'legacy',label:'Japan server',status:'running',ipv4:['192.0.2.1'],region:'jp-osa',type:'g6-nanode-1',password_saved:true};
const responses={'/accounts':{accounts:[{id:'legacy',name:'我的 Linode 账号'}]},'/instances':{instances:[instance]},'/telegram/settings':{configured:false,enabled:false,chat_id:''},'/dns/providers':{providers:[]},'/monitor':{instances:[]},'/wp2/nodes':{nodes:Array.from({length:55},(_,index)=>({id:929+index,name:'日本节点'+index,sort:'Hysteria2'}))},'/catalog/regions':{data:[{id:'jp-osa',label:'Osaka'}]},'/catalog/types':{data:[{id:'g6-nanode-1',label:'Nanode',price:{monthly:5,hourly:0.0075}}]},'/catalog/images':{data:[{id:'linode/debian12',label:'Debian 12'}]},'/instances/5/password':{root_pass:'mock-password'}};
const context={document:{getElementById:get,createElement:el},confirm:()=>true,prompt:()=>promptValue,setInterval(){},setTimeout,
fetch:async(path,options)=>{calls.push({path,options});const key=path.slice(4).split('?')[0];let data;
if(key==='/dns/discover')data={zones:['example.com'],suggested_zone:'example.com',node_domain:'jp.example.com'};
else if(key==='/telegram/settings'&&options.method==='POST')data={saved:true};
else if(key==='/telegram/test')data={message:'测试消息已发送'};
else if(key==='/dns/providers'&&options.method==='POST')data={saved:true};
else if(key==='/wp2/session'){if(options.method==='POST')connected=true;if(options.method==='DELETE')connected=false;data={connected}}
else if(key==='/linode/proxy')data={configured:true,address:'socks5://proxy.example:1080'};
else if(options.method==='POST'&&key==='/instances')data={...instance,password_saved:true};
else if(options.method==='POST'&&key==='/deployments/install')data={job_id:'mock-job'};
else if(key==='/deployments/mock-job')data={job_id:'mock-job',status:'success',log:'mock deployment validated'};
else if(options.method==='POST'||options.method==='DELETE')data={deleted:true};
else {assert(key in responses,key);data=responses[key]}
return {ok:true,json:async()=>data};}};
vm.createContext(context);vm.runInContext(source,context);const tick=()=>new Promise(setImmediate);
(async()=>{
await tick();assert.equal(get('account').value,'legacy');assert.equal(get('instance').value,'5');assert(get('instances').innerHTML.includes('我的 Linode 账号'));assert(get('instances').innerHTML.includes('192.0.2.1'));assert(get('instances').innerHTML.includes('jp-osa'));assert(get('dnstarget').textContent.includes('192.0.2.1'));
get('wp2email').value='admin@example.com';get('wp2password').value='mock-login-password';get('wp2code').value='123456';await context.connectWP2();assert.equal(connected,true);assert.equal(get('wp2password').value,'');assert.equal(get('wp2code').value,'');assert.equal(get('node').options.length,56);assert.equal((get('nodes').innerHTML.match(/<tr>/g)||[]).length,11);assert(get('nodespage').textContent.includes('/ 6'));get('nodesearch').value='929';context.renderNodes();assert.equal((get('nodes').innerHTML.match(/<tr>/g)||[]).length,2);get('nodesearch').value='';context.renderNodes();
get('tgtoken').value='123456:mock-test-token-123456789012345';get('tgchat').value='-100123456';get('tgenabled').checked=true;await context.saveTelegram();assert.equal(get('tgtoken').value,'');await context.testTelegram();assert.equal(get('tgtest').disabled,false);
get('dnsprovider').value='cloudflare';get('dnszone').value='example.com';get('dnstoken').value='mock-cf-key';get('dnsenabled').checked=true;await context.discoverDNS();assert.equal(get('dnszone').value,'example.com');await context.saveDNS();assert.equal(get('dnstoken').value,'');
get('proxyurl').value='socks5://user:secret@proxy.example:1080';await context.saveProxy();assert.equal(get('proxyurl').value,'');
await context.catalogs();get('createlabel').value='new-node';get('createregion').value='jp-osa';get('createtype').value='g6-nanode-1';get('createimage').value='linode/debian12';get('createpass').value='mock-root-password';
const first=context.createInstance();await context.createInstance();await first;
assert.equal(calls.filter(x=>x.options.method==='POST'&&x.path==='/api/instances?account_id=legacy').length,1);assert.equal(get('createpass').value,'');
get('openallports').checked=true;get('useproxy').checked=true;get('createpass').value='mock-root-password';await context.createInstance();assert(calls.some(x=>x.options.method==='POST'&&x.path==='/api/instances?account_id=legacy&use_proxy=true'));
await context.power(5,'boot');assert(calls.some(x=>x.path==='/api/instances/5/boot?account_id=legacy&use_proxy=true'));
get('node').value='929';get('instance').value='-1';await context.install();assert(!calls.some(x=>x.path.startsWith('/api/deployments/install')));
get('instance').value='5';await context.install();await tick();const installation=calls.find(x=>x.path.startsWith('/api/deployments/install'));assert.equal(JSON.parse(installation.options.body).target_id,929);assert.equal(JSON.parse(installation.options.body).instance_id,5);assert.equal(get('installbutton').disabled,false);
await context.instanceOperation(instance,'password');assert.equal(get('savedpassword').value,'mock-password');
promptValue='wrong';await context.instanceOperation(instance,'delete');assert(!calls.some(x=>x.options.method==='DELETE'&&x.path.startsWith('/api/instances/5')));
promptValue='5';await context.instanceOperation(instance,'delete');assert(calls.some(x=>x.options.method==='DELETE'&&x.path.includes('confirm_id=5')));
await context.disconnectWP2();assert.equal(connected,false);assert.equal(get('node').options.length,0);
console.log('PASS dashboard: account/instance selection, IP/region, wp2 login, secret clearing, optional proxy create/boot, duplicate guards, automatic job polling, password reveal and confirmed deletion. All APIs mocked.');
})().catch(error=>{console.error(error);process.exitCode=1});
