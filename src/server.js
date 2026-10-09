import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase, validateData, verifyPassword, passwordHash, token, digest, root } from './store.js';
const SESSION_MS=8*60*60*1000;
const DUMMY_HASH='scrypt$00000000000000000000000000000000$'+'00'.repeat(64);
const files={'/':'index.html','/index.html':'index.html','/styles.css':'styles.css','/app.js':'app.js','/admin':'admin.html','/admin/':'admin.html','/admin.js':'admin.js','/admin.css':'admin.css'};
class HttpError extends Error {constructor(status,message){super(message);this.status=status;}}
async function body(req){let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>512*1024)throw new HttpError(413,'Слишком большой запрос (максимум 512 КБ).');chunks.push(chunk);}try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/,''));if(!value||typeof value!=='object'||Array.isArray(value))throw Error('shape');return value;}catch{throw new HttpError(400,'Неверный JSON.');}}
function cookie(req){return req.headers.cookie?.split(';').map(x=>x.trim()).find(x=>x.startsWith('photo_session='))?.slice(14)||'';}
function securityHeaders(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");}
export function createApp({db=openDatabase(),secureCookies=process.env.NODE_ENV==='production',appOrigin=process.env.APP_ORIGIN||'',trustProxy=process.env.TRUST_PROXY==='1'}={}){
  const send=(res,status,value)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value));};
  function session(req){const raw=cookie(req);if(!/^[A-Za-z0-9_-]{43}$/.test(raw))return null;return db.prepare('SELECT sessions.*, admins.username FROM sessions JOIN admins ON admins.id=sessions.admin_id WHERE token_hash=? AND expires_at>?').get(digest(raw),Date.now());}
  function authenticated(req){const s=session(req);if(!s)throw new HttpError(401,'Войдите в кабинет администратора.');return s;}
  function originCheck(req){const expected=appOrigin||(secureCookies?'https:':'http:')+'//'+req.headers.host;if(req.headers.origin!==expected)throw new HttpError(403,'Запрос с другого сайта запрещён.');}
  function writeAuth(req){originCheck(req);const s=authenticated(req);if(req.headers['x-csrf-token']!==s.csrf)throw new HttpError(403,'Обновите страницу кабинета и повторите действие.');return s;}
  function setCookie(res,value,maxAge=SESSION_MS/1000){res.setHeader('Set-Cookie',`photo_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secureCookies?'; Secure':''}`);}
  function regulations(){const row=db.prepare('SELECT * FROM regulations WHERE id=1').get();return {data:JSON.parse(row.document),revision:row.revision,updatedAt:row.updated_at};}
  async function handle(req,res){securityHeaders(res);const path=new URL(req.url,'http://localhost').pathname;
    if(path==='/api/regulations'&&req.method==='GET'){const doc=regulations();doc.data.quizzes=doc.data.quizzes.map(({correctOptionId,explanation,...q})=>q);send(res,200,doc);return;}
    if(path==='/api/admin/document'&&req.method==='GET'){authenticated(req);send(res,200,regulations());return;}
    if(path==='/api/tests/submit'&&req.method==='POST'){
      originCheck(req);const input=await body(req);const current=regulations();if(input.revision!==current.revision)throw new HttpError(409,'Вопросы обновлены администратором. Обновите тест и попробуйте снова.');const questions=current.data.quizzes.filter(q=>q.role===input.role);if(!questions.length)throw new HttpError(400,'Для этой роли пока нет вопросов.');if(!input.answers||typeof input.answers!=='object'||Array.isArray(input.answers))throw new HttpError(400,'Выберите ответы.');let correct=0;const feedback=questions.map(q=>{if(!q.options.some(o=>o.id===input.answers[q.id]))throw new HttpError(400,'Ответьте на все вопросы.');const ok=input.answers[q.id]===q.correctOptionId;if(ok)correct++;return {id:q.id,correct:ok,correctOptionId:q.correctOptionId,explanation:q.explanation,source:q.source};});send(res,200,{correct,total:questions.length,feedback});return;
    }
    if(path==='/api/admin/session'&&req.method==='GET'){const s=session(req);send(res,200,{authenticated:!!s,username:s?.username||null,csrf:s?.csrf||null});return;}
    if(path==='/api/admin/login'&&req.method==='POST'){
      originCheck(req);const input=await body(req);const ip=trustProxy?String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim():req.socket.remoteAddress;
      const key=digest(ip||'unknown');const now=Date.now();db.prepare('DELETE FROM login_attempts WHERE reset_at<=?').run(now);
      const limit=db.prepare('SELECT attempts,reset_at FROM login_attempts WHERE key=?').get(key);if(limit?.attempts>=10){res.setHeader('Retry-After',Math.ceil((limit.reset_at-now)/1000));throw new HttpError(429,'Слишком много попыток. Повторите вход через 15 минут.');}
      // Reserve an attempt before password hashing, including parallel requests.
      db.prepare('INSERT INTO login_attempts (key,attempts,reset_at) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=attempts+1').run(key,now+15*60*1000);
      const admin=typeof input.username==='string'?db.prepare('SELECT * FROM admins WHERE username=?').get(input.username):null;
      const valid=await verifyPassword(input.password,admin?.password_hash||DUMMY_HASH);
      if(!admin||!valid)throw new HttpError(401,'Неверный логин или пароль.');
      db.prepare('DELETE FROM login_attempts WHERE key=?').run(key);db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(now);
      const raw=token(),csrf=token();db.prepare('INSERT INTO sessions (token_hash,admin_id,csrf,expires_at) VALUES (?,?,?,?)').run(digest(raw),admin.id,csrf,now+SESSION_MS);setCookie(res,raw);send(res,200,{authenticated:true,username:admin.username,csrf});return;
    }
    if(path==='/api/admin/logout'&&req.method==='POST'){const s=writeAuth(req);db.prepare('DELETE FROM sessions WHERE token_hash=?').run(s.token_hash);setCookie(res,'',0);send(res,200,{ok:true});return;}
    if(path==='/api/admin/validate'&&req.method==='POST'){
      const input=await body(req);writeAuth(req);try{send(res,200,{data:validateData(input)});}catch(e){throw new HttpError(400,e.message);}return;
    }
    if(path==='/api/admin/regulations'&&req.method==='PUT'){
      const input=await body(req);writeAuth(req);if(!Number.isSafeInteger(input.revision)||input.revision<1)throw new HttpError(400,'Неверная версия документа.');let document;try{document=validateData(input.data);}catch(e){throw new HttpError(400,e.message);}
      const updatedAt=new Date().toISOString();const result=db.prepare('UPDATE regulations SET document=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?').run(JSON.stringify(document),updatedAt,input.revision);
      if(result.changes!==1)throw new HttpError(409,'База уже изменена в другой вкладке. Скачайте свой черновик, затем загрузите актуальную версию.');send(res,200,regulations());return;
    }
    if(path==='/api/admin/password'&&req.method==='POST'){
      const s=writeAuth(req);const input=await body(req);const admin=db.prepare('SELECT password_hash FROM admins WHERE id=?').get(s.admin_id);if(!await verifyPassword(input.currentPassword,admin.password_hash))throw new HttpError(400,'Текущий пароль указан неверно.');let hash;try{hash=await passwordHash(input.newPassword);}catch(e){throw new HttpError(400,e.message);}
      // Recheck the old hash after asynchronous work, then revoke every session.
      const result=db.prepare('UPDATE admins SET password_hash=? WHERE id=? AND password_hash=?').run(hash,s.admin_id,admin.password_hash);if(result.changes!==1)throw new HttpError(409,'Пароль уже изменён. Войдите заново.');db.prepare('DELETE FROM sessions WHERE admin_id=?').run(s.admin_id);setCookie(res,'',0);send(res,200,{ok:true});return;
    }
    if(req.method!=='GET'&&req.method!=='HEAD')throw new HttpError(405,'Метод не поддерживается.');
    if(!files[path])throw new HttpError(404,'Страница не найдена.');
    const file=files[path];const content=await readFile(resolve(root,'public',file));const type=file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':'text/html';res.writeHead(200,{'Content-Type':`${type}; charset=utf-8`,'Cache-Control':'no-cache'});res.end(req.method==='HEAD'?undefined:content);
  }
  const server=createServer((req,res)=>{handle(req,res).catch(e=>{if(!e.status)console.error('Ошибка сервера:',e.message);if(!res.headersSent)send(res,e.status||500,{error:e.status?e.message:'Не удалось выполнить действие. Повторите позже.'});else res.end();});});
  server.requestTimeout=30000;server.headersTimeout=15000;
  return {server,db};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.env.NODE_ENV==='production'&&!process.env.APP_ORIGIN){console.error('Для production укажите APP_ORIGIN=https://your-domain.example');process.exit(1);}
  const {server,db}=createApp();const port=Number(process.env.PORT||4173),host=process.env.HOST||'127.0.0.1';server.listen(port,host,()=>console.log(`PHOTO LAB: http://${host}:${port}\nКабинет администратора: /admin`));
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{server.close(()=>{db.close();process.exit(0);});});
}
