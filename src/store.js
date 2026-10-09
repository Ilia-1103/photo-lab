import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const derive = promisify(scrypt);
export const digest = value => createHash('sha256').update(value).digest('hex');
export const token = () => randomBytes(32).toString('base64url');
export function validateData(value) {
  const roles = ['Фотограф','Печатник','Продажник','Старший смены','Управляющий','Офис'];
  if(value?.schemaVersion !== 2 || value.company !== 'PHOTO LAB' || !Array.isArray(value.sections) || value.sections.length > 200 || !Array.isArray(value.categories)) throw Error('Неподходящая структура регламента.');
  const allowed = new Set(['duties','forbidden','standards','interaction']);
  const cats = new Set();
  for(const c of value.categories){if(!allowed.has(c.id)||cats.has(c.id)||typeof c.title!=='string'||!c.title.trim()||c.title.length>100)throw Error('Проверьте тематические блоки.');cats.add(c.id);}
  if(cats.size!==4)throw Error('Нужны четыре тематических блока.');
  if(!Array.isArray(value.quizzes)||value.quizzes.length>200)throw Error('Проверьте список вопросов.');
  const qids=new Set();
  for(const q of value.quizzes){if(typeof q.id!=='string'||!q.id||q.id.length>80||qids.has(q.id)||!roles.includes(q.role)||typeof q.question!=='string'||!q.question.trim()||q.question.length>1000||!Array.isArray(q.options)||q.options.length<2||q.options.length>6||typeof q.explanation!=='string'||q.explanation.length>5000||typeof q.source!=='string'||q.source.length>100)throw Error('Проверьте вопрос, роль и варианты ответа.');
    const optionIds=new Set();for(const o of q.options){if(typeof o.id!=='string'||!o.id||o.id.length>30||optionIds.has(o.id)||typeof o.text!=='string'||!o.text.trim()||o.text.length>1000)throw Error('Проверьте варианты ответа.');optionIds.add(o.id);}if(!optionIds.has(q.correctOptionId))throw Error('Для каждого вопроса выберите правильный ответ.');qids.add(q.id);
  }
  const ids = new Set();
  for(const s of value.sections){if(typeof s.id!=='string'||!s.id.trim()||s.id.length>30||ids.has(s.id.trim())||typeof s.title!=='string'||!s.title.trim()||s.title.length>150||!cats.has(s.category)||!roles.includes(s.role)||!Array.isArray(s.items)||!s.items.length||s.items.length>100||s.items.some(x=>typeof x!=='string'||!x.trim()||x.length>20000))throw Error('Проверьте номер, роль, название и текст каждого пункта.');ids.add(s.id.trim());}
  return {schemaVersion:2,company:'PHOTO LAB',roles,categories:value.categories.map(c=>({id:c.id,title:c.title.trim()})),sections:value.sections.map(s=>({id:s.id.trim(),title:s.title.trim(),role:s.role,category:s.category,items:s.items.map(x=>x.trim())})),quizzes:value.quizzes.map(q=>({id:q.id,role:q.role,question:q.question.trim(),options:q.options.map(o=>({id:o.id,text:o.text.trim()})),correctOptionId:q.correctOptionId,explanation:q.explanation.trim(),source:q.source.trim()}))};
}
export function openDatabase(filename = process.env.DB_PATH || resolve(root,'data/photo-lab.sqlite')) {
  if(filename!==':memory:')mkdirSync(dirname(resolve(filename)),{recursive:true});
  const db=new DatabaseSync(filename,{timeout:5000});
  db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db.exec(readFileSync(resolve(root,'src/schema.sql'),'utf8'));
  let seed=JSON.parse(readFileSync(resolve(root,'src/seed.json'),'utf8').replace(/^\uFEFF/,''));
  if(seed.schemaVersion===1){seed={...seed,schemaVersion:2,sections:seed.sections.map(s=>({...s,role:'Фотограф'})),quizzes:[]};}
  seed=validateData(seed);
  db.prepare('INSERT OR IGNORE INTO regulations (id, document, revision, updated_at) VALUES (1, ?, 1, ?)').run(JSON.stringify(seed),new Date().toISOString());
  return db;
}
export async function passwordHash(password) {
  if(typeof password!=='string'||password.length<12||password.length>128)throw Error('Пароль должен содержать от 12 до 128 символов.');
  const salt=randomBytes(16).toString('hex');
  const key=await derive(password,salt,64,{N:32768,r:8,p:1,maxmem:64*1024*1024});
  return `scrypt$${salt}$${key.toString('hex')}`;
}
export async function verifyPassword(password, hash) {
  if(typeof password!=='string'||password.length>128)return false;
  const [algorithm,salt,expected]=hash.split('$');
  if(algorithm!=='scrypt'||!salt||!expected)return false;
  const key=await derive(password,salt,64,{N:32768,r:8,p:1,maxmem:64*1024*1024});
  const target=Buffer.from(expected,'hex');return target.length===key.length&&timingSafeEqual(target,key);
}
export async function setAdministrator(db,username,password){
  if(!/^[A-Za-z0-9_.-]{3,50}$/.test(username))throw Error('Логин: 3–50 латинских букв, цифр или символов _ . -');
  const hash=await passwordHash(password);
  db.exec('BEGIN IMMEDIATE');
  try{db.prepare('INSERT INTO admins (id, username, password_hash) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash').run(username,hash);db.prepare('DELETE FROM sessions').run();db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
}
