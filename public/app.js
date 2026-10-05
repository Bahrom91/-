const { startAuthentication, startRegistration } = SimpleWebAuthnBrowser;

let vault = { version: 1, accounts: [], numbers: [] };
let vaultKey = null;
let vaultSalt = null;

const $ = id => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64u(bytes) {
  let s = '';
  bytes = new Uint8Array(bytes);
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function unb64u(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
async function deriveKey(pin, password, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin + '|' + password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:unb64u(salt),iterations:310000,hash:'SHA-256'},
    base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']
  );
}
async function encryptVault(data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, vaultKey, enc.encode(JSON.stringify(data)));
  return {ciphertext:b64u(ct),iv:b64u(iv)};
}
async function decryptVault(payload) {
  if (!payload.ciphertext) return {version:1,accounts:[],numbers:[]};
  const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64u(payload.iv)},vaultKey,unb64u(payload.ciphertext));
  return JSON.parse(dec.decode(pt));
}
async function api(url, options={}) {
  const r = await fetch(url,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});
  const data = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(data.error || 'Xatolik');
  return data;
}
function msg(text){ $('message').textContent=text||''; }

async function step1() {
  const pin = $('pin').value;
  if (!/^\d+$/.test(pin)) return msg('PIN faqat raqamlardan iborat bo‘lishi kerak.');
  $('step1').classList.add('hidden'); $('step2').classList.remove('hidden'); msg('');
}
async function step2() {
  const p = $('letters').value;
  if (!/^[A-Za-z]+$/.test(p)) return msg('2-etap faqat harflardan iborat bo‘lishi kerak.');
  $('step2').classList.add('hidden'); $('step3').classList.remove('hidden'); msg('');
}
async function biometricLogin() {
  try {
    const pin = $('pin').value, password = $('letters').value;
    const s = await api('/api/status');
    vaultSalt = s.vaultSalt;
    vaultKey = await deriveKey(pin,password,vaultSalt);

    await api('/api/login/step1',{method:'POST',body:JSON.stringify({pin,password})});
    const options = await api('/api/passkey/options');
    const assertion = await startAuthentication({optionsJSON:options});
    await api('/api/passkey/verify',{method:'POST',body:JSON.stringify(assertion)});

    const encrypted = await api('/api/vault');
    vault = await decryptVault(encrypted);
    showApp();
  } catch(e) { msg(e.message || 'Kirish amalga oshmadi.'); }
}
async function registerPasskey() {
  try {
    const options = await api('/api/passkey/register/options');
    const att = await startRegistration({optionsJSON:options});
    await api('/api/passkey/register/verify',{method:'POST',body:JSON.stringify(att)});
    alert('Biometrika muvaffaqiyatli qo‘shildi.');
  } catch(e) { msg(e.message || 'Biometrika qo‘shilmadi.'); }
}
function showApp() {
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  render();
}
function categories() {
  return [
    ['📱','Social','Instagram, TikTok, Facebook, Telegram, Google, iCloud'],
    ['🎮','Games','EFOD/BIL va boshqa o‘yinlar'],
    ['📞','Numbers','Telefon raqamlari'],
    ['📦','Other','Boshqa ma’lumotlar']
  ];
}
function render() {
  $('categories').innerHTML = categories().map(([i,n,d])=>`<div class="category" data-cat="${n}"><span>${i}</span><b>${n}</b><small>${d}</small></div>`).join('');
  const q = $('search').value.toLowerCase();
  const all = vault.accounts.filter(x => JSON.stringify(x).toLowerCase().includes(q));
  $('items').innerHTML = all.length ? all.map((x,i)=>`
    <div class="vault-item">
      <h3>${esc(x.site||'Untitled')}</h3>
      <div><b>Login:</b> ${esc(x.username||'—')}</div>
      <div><b>Email:</b> ${esc(x.email||'—')}</div>
      <div><b>Telefon:</b> ${esc(x.phone||'—')}</div>
      <div><b>Parol:</b> <span id="pw-${i}">••••••••</span></div>
      ${x.note?`<div class="muted">${esc(x.note)}</div>`:''}
      <div class="row">
        <button class="mini" onclick="reveal(${i})">👁 Ko‘rish</button>
        <button class="mini" onclick="copyPw(${i})">📋 Nusxa</button>
        <button class="mini danger" onclick="removeItem(${i})">🗑 O‘chirish</button>
      </div>
    </div>`).join('') : '<div class="muted">Hozircha hech narsa yo‘q.</div>';
}
function esc(s){return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function reveal(i){const el=$(`pw-${i}`);el.textContent=el.textContent.includes('•')?vault.accounts[i].password:'••••••••'}
async function copyPw(i){await navigator.clipboard.writeText(vault.accounts[i].password||'');alert('Nusxalandi.')}
async function saveVault() {
  const e = await encryptVault(vault);
  await api('/api/vault',{method:'PUT',body:JSON.stringify(e)});
}
function addItem() {
  $('modal').classList.remove('hidden');
}
async function saveItem() {
  const item={site:$('site').value.trim(),username:$('username').value.trim(),password:$('accountPassword').value,email:$('email').value.trim(),phone:$('phone').value.trim(),note:$('note').value.trim()};
  if(!item.site || !item.password) return alert('Sayt va parolni kiriting.');
  vault.accounts.push(item); await saveVault(); render(); $('modal').classList.add('hidden');
  ['site','username','accountPassword','email','phone','note'].forEach(id=>$(id).value='');
}
async function removeItem(i){if(confirm('O‘chirishni xohlaysizmi?')){vault.accounts.splice(i,1);await saveVault();render()}}
async function changeCredentials(){
  const body={
    oldPin:$('oldPin').value,oldPassword:$('oldPassword').value,
    newPin:$('newPin').value,newPassword:$('newPassword').value
  };
  if(!/^\d+$/.test(body.newPin)||!/^[A-Za-z]+$/.test(body.newPassword))return alert('Yangi PIN faqat raqam, parol faqat harf bo‘lsin.');
  try{
    await api('/api/security/change',{method:'POST',body:JSON.stringify(body)});
    vaultKey=await deriveKey(body.newPin,body.newPassword,vaultSalt);
    await saveVault();
    alert('Kirish ma’lumotlari o‘zgartirildi.');
    $('settingsModal').classList.add('hidden');
  }catch(e){alert(e.message)}
}
$('continue1').onclick=step1;
$('continue2').onclick=step2;
$('biometric').onclick=biometricLogin;
$('register').onclick=registerPasskey;
$('add').onclick=addItem;
$('save').onclick=saveItem;
$('close').onclick=()=>$('modal').classList.add('hidden');
$('settings').onclick=()=>$('settingsModal').classList.remove('hidden');
$('closeSettings').onclick=()=>$('settingsModal').classList.add('hidden');
$('changeCredentials').onclick=changeCredentials;
$('addPasskey').onclick=registerPasskey;
$('logout').onclick=async()=>{await api('/api/logout',{method:'POST'});location.reload()};
$('search').oninput=render;

(async()=>{
  try{
    const s=await api('/api/status');
    if(!s.initialized) msg('Vault hali sozlanmagan.');
    $('register').classList.remove('hidden');
  }catch{}
})();
