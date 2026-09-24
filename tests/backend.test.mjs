import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
let mf, db;
const origin='https://example.com';
before(async()=>{
 mf=new Miniflare(convertV4MiniflareOptions({modules:true,scriptPath:'dist/worker/index.js',compatibilityDate:'2026-09-24',compatibilityFlags:['nodejs_compat'],d1Databases:['DB']}));
 db=await mf.getD1Database('DB');
 const schema=await readFile('migrations/0001_initial.sql','utf8');
 await db.batch(schema.split(';').map(s=>s.trim()).filter(Boolean).map(s=>db.prepare(s)));
});
after(async()=>{await mf?.dispose();});
async function call(path, method='GET', data, cookie, extra={}) {
 return mf.dispatchFetch(origin+path,{method,headers:{...(method!=='GET'?{'Origin':origin,'Content-Type':'application/json'}:{}),...(cookie?{Cookie:cookie}:{}),...extra},...(data!==undefined?{body:JSON.stringify(data)}:{})});
}
async function register(username) {const response=await call('/api/auth/register','POST',{username,password:'correct horse battery staple'});assert.equal(response.status,200,await response.clone().text());return response.headers.get('set-cookie').split(';')[0];}
test('authentication, permission boundaries, validation and sessions',async()=>{
 assert.equal((await call('/api/sets','POST',{name:'test'})).status,401);
 assert.equal((await call('/api/auth/register','POST',{username:'xx',password:'short'})).status,400);
 assert.equal((await call('/api/auth/login','POST',{},null,{Origin:'https://evil.example'})).status,403);
 const alice=await register('alice'); const bob=await register('bob');
 const cookieResponse=await call('/api/auth/login','POST',{username:'alice',password:'correct horse battery staple'});
 const header=cookieResponse.headers.get('set-cookie');assert.match(header,/HttpOnly/);assert.match(header,/Secure/);assert.match(header,/SameSite=Strict/);
 assert.equal((await call('/api/auth/login','POST',{username:'alice',password:'wrong password long enough'})).status,401);
 const me=await (await call('/api/auth/me','GET',undefined,alice)).json();assert.equal(me.user.username,'alice');
 const row=await db.prepare('SELECT password_hash FROM users WHERE username=?').bind('alice').first();assert.equal(row.password_hash.length,64);assert.notEqual(row.password_hash,'correct horse battery staple');
 const data={name:'Test set',subject:'Science',cards:[{front:'Question?',back:'Answer'}],author:'bob',admin:true,user_id:me.user.id};
 const published=await call('/api/sets','POST',data,alice);assert.equal(published.status,201);const set=await published.json();assert.equal(set.author,'alice');
 assert.equal((await call('/api/sets/'+set.id,'DELETE',undefined,bob)).status,404);
 assert.equal((await call('/api/sets','POST',{...data,cards:[]},alice)).status,400);
 assert.equal((await call('/api/sets','POST',{...data,cards:[{front:'x'.repeat(140000),back:'a'}]},alice)).status,413);
 const message=await call('/api/chat','POST',{text:'hello',author:'bob',admin:true},alice);assert.equal(message.status,201);assert.equal((await message.json()).author,'alice');
 await db.prepare('UPDATE users SET muted=1 WHERE username=?').bind('bob').run();
 assert.equal((await call('/api/chat','POST',{text:'muted',muted:false},bob)).status,403);
 assert.equal((await call('/api/chat','DELETE',undefined,alice)).status,404);
 assert.equal((await call('/api/sets/'+set.id,'DELETE',undefined,alice)).status,200);
 assert.equal((await call('/api/sets')).headers.get('cache-control'),'no-store');
 assert.match((await call('/api/sets')).headers.get('content-security-policy'),/script-src 'self'/);
 await call('/api/auth/logout','POST',undefined,alice);
 assert.equal((await call('/api/chat','POST',{text:'no'},alice)).status,401);
 await db.prepare('UPDATE sessions SET expires=0').run();
 assert.equal((await (await call('/api/auth/me','GET',undefined,bob)).json()).user,null);
});
test('rate limiting rejects excess account attempts',async()=>{
 let response;
 for(let i=0;i<16;i++) response=await call('/api/auth/login','POST',{});
 assert.equal(response.status,429);assert.ok(response.headers.get('retry-after'));
});
