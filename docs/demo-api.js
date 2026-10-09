'use strict';
(()=>{
const saveMessage='Сохранение недоступно в демоверсии. Сначала разместите серверную версию сайта на хостинге с поддержкой Node.js и базы данных — тогда изменения смогут сохраняться.';
let authenticated=false,initialPromise;
const clone=value=>structuredClone(value);
async function initial(){if(!initialPromise)initialPromise=fetch('data.json',{cache:'no-store'}).then(async r=>{if(!r.ok)throw Error('Не удалось загрузить демонстрационные данные.');return r.json();}).catch(e=>{initialPromise=null;throw e;});return initialPromise;}
function validateData(value) {
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

async function request(path,options={}){
const method=options.method||'GET';const input=options.body?JSON.parse(options.body):{};
if(path==='/api/admin/session')return {authenticated,username:authenticated?'admin':null,csrf:null};
if(path==='/api/admin/login'){
if(input.username!=='admin'||input.password!=='PhotoLabDemo2026!')throw Error('Неверный логин или пароль. Используйте демонстрационные данные над формой.');authenticated=true;return {authenticated:true,username:'admin',csrf:null};}
if(path==='/api/admin/logout'){authenticated=false;return {ok:true};}
if(path.startsWith('/api/admin/')&&!authenticated)throw Error('Войдите в демонстрационный кабинет.');
if(path==='/api/admin/regulations'||path==='/api/admin/password')throw Error(saveMessage);
if(path==='/api/admin/validate')return {data:validateData(input)};
const source=await initial();
if(path==='/api/admin/document')return {data:clone(source),revision:1,updatedAt:null};
if(path==='/api/regulations'){const data=clone(source);data.quizzes=data.quizzes.map(({correctOptionId,explanation,...q})=>q);return {data,revision:1,updatedAt:null};}
if(path==='/api/tests/submit'){
const questions=source.quizzes.filter(q=>q.role===input.role);if(!questions.length)throw Error('Для этой роли пока нет вопросов.');let correct=0;const feedback=questions.map(q=>{if(!q.options.some(o=>o.id===input.answers?.[q.id]))throw Error('Ответьте на все вопросы.');const ok=q.correctOptionId===input.answers[q.id];if(ok)correct++;return {id:q.id,correct:ok,correctOptionId:q.correctOptionId,explanation:q.explanation,source:q.source};});return {correct,total:questions.length,feedback};}
throw Error('Это действие недоступно в демоверсии.');
}
window.PhotoLabDemo=Object.freeze({request,saveMessage});
})();
