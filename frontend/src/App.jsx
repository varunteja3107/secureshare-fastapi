import React, { useEffect, useMemo, useState } from 'react';
import { ShieldCheck, LayoutDashboard, Upload, Download, History, KeyRound, Activity, LogOut, RefreshCw, FileLock2, FileText, Copy, Check, AlertTriangle, LockKeyhole, Clock3, Trash2, ArrowUpRight, Eye, EyeOff, Menu } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
const nav = [
  ['Dashboard', LayoutDashboard], ['Send securely', Upload], ['Receive', Download],
  ['Transfer history', History], ['Key management', KeyRound], ['Security activity', Activity]
];
const fmt = (d) => { try { return new Date(d).toLocaleString(); } catch { return d || ''; } };
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const random = n => crypto.getRandomValues(new Uint8Array(n));
async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:310000, hash:'SHA-256'}, material, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encryptBytes(bytes, passphrase) {
  const salt = random(16), iv = random(12), key = await deriveKey(passphrase, salt);
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, bytes);
  return {version:1, algorithm:'AES-256-GCM', kdf:'PBKDF2-SHA-256', iterations:310000, salt:b64(salt), iv:b64(iv), ciphertext:b64(cipher)};
}
async function decryptBytes(pkg, passphrase) {
  if (!pkg || pkg.algorithm !== 'AES-256-GCM') throw new Error('Unsupported encrypted package.');
  const key = await deriveKey(passphrase, unb64(pkg.salt));
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(pkg.iv)}, key, unb64(pkg.ciphertext)));
}
function downloadBytes(bytes, filename, type='application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], {type})); const a=document.createElement('a'); a.href=url; a.download=filename; a.click(); URL.revokeObjectURL(url);
}
function App() {
  const [page,setPage] = useState('Dashboard'), [api,setApi] = useState('Checking…'), [loading,setLoading] = useState(false);
  const [history,setHistory] = useState(() => { try{return JSON.parse(sessionStorage.getItem('ss-history')||'[]')}catch{return[]} });
  const [transfers,setTransfers] = useState(() => { try{return JSON.parse(sessionStorage.getItem('ss-transfers')||'[]')}catch{return[]} });
  const [messageMode,setMessageMode] = useState(false), [file,setFile] = useState(null), [message,setMessage] = useState('');
  const [pass,setPass] = useState(''), [expiry,setExpiry] = useState('24'), [maxDownloads,setMaxDownloads] = useState('3');
  const [created,setCreated] = useState(null), [error,setError] = useState(''), [code,setCode] = useState(''), [receivePass,setReceivePass] = useState('');
  const [received,setReceived] = useState(null), [events,setEvents] = useState([]), [adminKey,setAdminKey] = useState(''), [eventType,setEventType] = useState('all'), [eventSearch,setEventSearch] = useState('');
  const [keyAlgo,setKeyAlgo] = useState('RSA-OAEP (3072-bit)'), [keys,setKeys] = useState(null), [pubFile,setPubFile] = useState(null), [backupFile,setBackupFile] = useState(null), [backupPass,setBackupPass] = useState('');
  const [toast,setToast] = useState('');
  const notify = s => {setToast(s); setTimeout(()=>setToast(''),2600)};
  async function health(){try{let r=await fetch(`${API}/api/health`);setApi(r.ok?'Connected':'Unavailable')}catch{setApi('Unavailable')}}
  useEffect(()=>{health()},[]);
  useEffect(()=>{sessionStorage.setItem('ss-history',JSON.stringify(history))},[history]);
  useEffect(()=>{sessionStorage.setItem('ss-transfers',JSON.stringify(transfers))},[transfers]);
  const addEvent = (type,detail) => setEvents(prev=>[{id:crypto.randomUUID(),type,detail,at:new Date().toISOString()},...prev]);
  const go = p => {setPage(p);setError('');setCreated(null);setReceived(null)};
  async function send() {
    setError('');setCreated(null);
    if(!pass || pass.length<12){setError('Use a transfer passphrase of at least 12 characters.');return}
    if(messageMode ? !message.trim() : !file){setError(messageMode?'Enter a message first.':'Choose a file first.');return}
    if(!messageMode && file.size>15*1024*1024){setError('This prototype allows files up to 15 MB.');return}
    setLoading(true);
    try {
      const plain = messageMode ? new TextEncoder().encode(message) : new Uint8Array(await file.arrayBuffer());
      const encrypted = await encryptBytes(plain,pass);
      const body={encrypted_package:encrypted,filename:messageMode?'secure-message.txt':file.name,transfer_type:messageMode?'message':'file',expiry_hours:Number(expiry),max_downloads:Number(maxDownloads)};
      const r=await fetch(`${API}/api/transfers`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const data=await r.json(); if(!r.ok) throw new Error(data.detail||'Could not create transfer.');
      const item={code:data.code,filename:body.filename,transfer_type:body.transfer_type,created_at:data.created_at,expires_at:data.expires_at,max_downloads:Number(maxDownloads),revoked:false};
      setCreated({...data,filename:item.filename,transfer_type:item.transfer_type});setTransfers(prev=>[item,...prev.filter(x=>x.code!==item.code)]);
      setHistory(prev=>[item,...prev.filter(x=>x.code!==item.code)]);addEvent('transfer_created',`Created ${item.transfer_type} transfer ${data.code}`);setPass('');setMessage('');setFile(null);
    } catch(e){setError(e.message||'Network error. Is the backend running?')} finally{setLoading(false)}
  }
  async function receive() {
    setError('');setReceived(null);
    if(!code.trim()||!receivePass){setError('Enter both the transfer code and passphrase.');return}
    setLoading(true);
    try{
      const r=await fetch(`${API}/api/transfers/${encodeURIComponent(code.trim())}/retrieve`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
      const data=await r.json();if(!r.ok)throw new Error(data.detail||'Transfer could not be retrieved.');
      const plain=await decryptBytes(data.encrypted_package,receivePass);
      if(data.transfer_type==='message'){setReceived({kind:'message',text:new TextDecoder().decode(plain)});}
      else {downloadBytes(plain,data.filename||'received-file');setReceived({kind:'file',text:`Decrypted ${data.filename||'file'} and started download.`});}
      await fetch(`${API}/api/transfers/${encodeURIComponent(code.trim())}/confirm`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).catch(()=>{});
      addEvent('transfer_retrieved',`Retrieved transfer ${code.trim()}`);setReceivePass('');
    }catch(e){setError('Decryption/retrieval failed. Check the transfer code and passphrase. ('+(e.message||'unknown error')+')');addEvent('retrieve_failed',`Failed retrieval attempt for ${code.trim()}`)}finally{setLoading(false)}
  }
  async function revoke(item) {
    const token=prompt('Enter the revocation token shown when this transfer was created:');
    if(!token)return;
    try{const r=await fetch(`${API}/api/transfers/${encodeURIComponent(item.code)}/revoke`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revoke_token:token})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Revocation failed');setTransfers(p=>p.map(x=>x.code===item.code?{...x,revoked:true}:x));setHistory(p=>p.map(x=>x.code===item.code?{...x,revoked:true}:x));addEvent('transfer_revoked',`Revoked transfer ${item.code}`);notify('Transfer revoked');}catch(e){setError(e.message)}
  }
  async function generateKeys() {
    setError('');
    try {
      if(keyAlgo.startsWith('RSA')) {
        const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
        const pub=await crypto.subtle.exportKey('jwk',pair.publicKey), priv=await crypto.subtle.exportKey('jwk',pair.privateKey);
        setKeys({algorithm:'RSA-OAEP-3072',publicKey:pub,privateKey:priv});notify('RSA key pair generated in this browser');
      } else {
        const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey']);
        const pub=await crypto.subtle.exportKey('jwk',pair.publicKey), priv=await crypto.subtle.exportKey('jwk',pair.privateKey);
        setKeys({algorithm:'ECDH-P-256',publicKey:pub,privateKey:priv});notify('ECDH key pair generated in this browser');
      }
      addEvent('keys_generated',`Generated ${keyAlgo} key pair locally`);
    } catch(e){setError('Key generation failed: '+e.message)}
  }
  function exportPublic(){if(!keys)return;downloadBytes(new TextEncoder().encode(JSON.stringify({algorithm:keys.algorithm,publicKey:keys.publicKey},null,2)),'secureshare-public-key.json','application/json')}
  async function exportBackup(){
    if(!keys||!backupPass||backupPass.length<12){setError('Generate a key pair and enter a backup passphrase of at least 12 characters.');return}
    const encrypted=await encryptBytes(new TextEncoder().encode(JSON.stringify(keys)),backupPass);
    downloadBytes(new TextEncoder().encode(JSON.stringify(encrypted,null,2)),'secureshare-private-key-backup.json','application/json');notify('Encrypted private-key backup exported');
  }
  async function restoreBackup(){
    if(!backupFile||!backupPass){setError('Select a backup JSON and enter its passphrase.');return}
    try{const pkg=JSON.parse(await backupFile.text());const bytes=await decryptBytes(pkg,backupPass);setKeys(JSON.parse(new TextDecoder().decode(bytes)));notify('Private-key backup restored in this browser');addEvent('key_backup_restored','Restored encrypted private-key backup')}catch(e){setError('Backup could not be unlocked. Check the file and passphrase.')}
  }
  async function importPublic(){if(!pubFile){setError('Choose a public-key JSON file first.');return}try{const v=JSON.parse(await pubFile.text());if(!v.publicKey)throw new Error('Missing publicKey');notify(`Imported public key (${v.algorithm||'unknown algorithm'})`);addEvent('public_key_imported','Imported a recipient public-key JSON')}catch{setError('Invalid public-key JSON file.')}}
  async function loadEvents(){setError('');setLoading(true);try{const r=await fetch(`${API}/api/admin/events?event_type=${encodeURIComponent(eventType)}&q=${encodeURIComponent(eventSearch)}`,{headers:{'X-Admin-Key':adminKey}});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Unable to load security events');setEvents(d.events||[])}catch(e){setError(e.message)}finally{setLoading(false)}}
  const card = (icon,label,value,sub) => <div className="stat"><div className="stat-icon">{React.createElement(icon,{size:20})}</div><div className="eyebrow">{label}</div><div className="stat-value">{value}</div><div className="muted small">{sub}</div></div>;
  const banner = <div className="security-note"><ShieldCheck size={21}/><div><b>Security note</b><p>Content is encrypted in your browser with AES-GCM. This prototype still needs production hardening, HTTPS, authentication, rate limiting, security testing and durable deployment before handling company data.</p></div></div>;
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">S</span><span>Secure<span className="green">Share</span></span></div><div className="side-label">WORKSPACE</div><nav>{nav.map(([label,Icon])=><button key={label} className={'nav-item '+(page===label?'active':'')} onClick={()=>go(label)}><Icon size={17}/><span>{label}</span></button>)}</nav>
      <div className="sidebar-note"><ShieldCheck size={22}/><b>Encrypted in your browser</b><p>The server receives the encrypted package, not the original content or passphrase.</p></div>
      <div className="profile"><div className="avatar">SS</div><div><b>SecureShare user</b><small>Local prototype</small></div></div>
    </aside>
    <main className="main"><header className="topbar"><div><span className="crumb">Workspace</span><span className="slash">/</span><b>SecureShare</b></div><div className="top-actions"><span className={'api-dot '+(api==='Connected'?'':'off')}></span><span className="muted small">API: {api}</span><button className="icon-button" title="Refresh API status" onClick={health}><RefreshCw size={16}/></button><span className="prototype-pill">DEVELOPMENT PROTOTYPE</span></div></header>
      <section className="page-head"><div><div className="eyebrow">YOUR PRIVATE SHARING SPACE</div><h1>{({'Dashboard':'Your security command center.','Send securely':'Share with confidence.','Receive':'Receive securely.','Transfer history':'Your transfers.','Key management':'Manage your encryption keys.','Security activity':'Security activity'})[page]}</h1><p>Send confidential files and messages with browser-side encryption.</p></div><div className="hero-icon"><ShieldCheck size={30}/></div></section>
      {error&&<div className="alert error"><AlertTriangle size={18}/>{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
      {toast&&<div className="toast"><Check size={16}/>{toast}</div>}
      {page==='Dashboard'&&<><div className="section-heading"><div><div className="eyebrow">SECURITY OPERATIONS</div><h2>Security overview</h2><p className="muted">Your secure sharing activity, protection status, and workspace shortcuts.</p></div><button className="button secondary" onClick={()=>{health();notify('Dashboard refreshed')}}><RefreshCw size={16}/> Refresh</button></div>
        <div className="stats-grid">{card(Upload,'SESSION TRANSFERS',transfers.length,'Created in this browser session')}{card(Activity,'BACKEND HEALTH',api,'Latest frontend health-check status')}{card(LockKeyhole,'ENCRYPTION','AES-GCM','Content encrypted in your browser')}{card(History,'TRANSFER HISTORY',history.length,'Items currently available in session history')}</div>
        <div className="dashboard-grid"><section className="panel"><div className="eyebrow">WORKSPACE</div><h3>Quick actions</h3><div className="quick-grid">{[['Send securely','Encrypt and share a file or message',Upload],['Receive','Retrieve and decrypt a shared item',Download],['Transfer history',"Review this session's transfers",History]].map(([p,d,I])=><button className="quick-card" key={p} onClick={()=>go(p)}><span className="quick-icon"><I size={20}/></span><b>{p}</b><p>{d}</p></button>)}</div></section>
        <section className="panel"><div className="eyebrow">PROTECTION CENTER</div><h3>Security posture <span className="tag">Client-side encryption</span></h3>{[['Encrypted before upload','File/message encryption runs in the browser.'],['Passphrase required','Recipients need the correct secret to decrypt.'],['Transfer controls','Expiry, download limits, and revocation depend on transfer settings.'],['Protected audit API','Security events require administrator authentication.']].map(([a,b])=><div className="posture-row" key={a}><span className="checkmark"><Check size={15}/></span><div><b>{a}</b><p>{b}</p></div><span className="status">Enabled</span></div>)}</section></div>{banner}</>}
      {page==='Send securely'&&<section className="panel form-panel"><div className="panel-top"><div><div className="eyebrow">NEW TRANSFER</div><h3>What would you like to share?</h3></div><span className="tag"><LockKeyhole size={13}/> Private</span></div>
        <div className="segmented"><button className={!messageMode?'selected':''} onClick={()=>setMessageMode(false)}><Upload size={15}/> Share a file</button><button className={messageMode?'selected':''} onClick={()=>setMessageMode(true)}><FileText size={15}/> Send a message</button></div>
        {!messageMode?<label className="dropzone"><Upload size={25}/><b>{file?file.name:'Choose a file to protect'}</b><span>{file?`${(file.size/1024).toFixed(1)} KB · selected`:'Click here to browse your device'}</span><small>Maximum 15 MB in this prototype</small><input type="file" onChange={e=>setFile(e.target.files?.[0]||null)}/></label>:<label className="field"><span>Confidential message</span><textarea rows="5" value={message} onChange={e=>setMessage(e.target.value)} placeholder="Write the message you want to share…"/></label>}
        <label className="field"><span>Encryption method</span><select value="Passphrase encryption" disabled><option>Passphrase encryption</option></select></label>
        <label className="field"><span>Content encryption algorithm</span><select value="AES-256-GCM" disabled><option>AES-256-GCM</option></select></label>
        <label className="field"><span>Transfer passphrase</span><input type="password" autoComplete="new-password" value={pass} onChange={e=>setPass(e.target.value)} placeholder="At least 12 characters"/><small>Share this separately with your recipient. Do not send it alongside the transfer code.</small></label>
        <div className="two-fields"><label className="field"><span>Transfer expires in</span><select value={expiry} onChange={e=>setExpiry(e.target.value)}><option value="1">1 hour</option><option value="24">24 hours</option><option value="72">3 days</option><option value="168">7 days</option></select></label><label className="field"><span>Maximum retrievals</span><select value={maxDownloads} onChange={e=>setMaxDownloads(e.target.value)}>{[1,2,3,5,10].map(n=><option value={n} key={n}>{n} {n===1?'retrieval':'retrievals'}</option>)}</select></label></div>
        <button className="button primary full" onClick={send} disabled={loading}>{loading?'Encrypting and creating…':<><LockKeyhole size={17}/> Encrypt and create transfer <ArrowUpRight size={17}/></>}</button>
        {created&&<div className="result-card"><div className="result-head"><Check size={20}/><div><b>Encrypted transfer created</b><p>Share the code and passphrase through separate channels.</p></div></div><label className="field"><span>Transfer code</span><div className="copy-row"><code>{created.code}</code><button className="button secondary" onClick={()=>{navigator.clipboard?.writeText(created.code);notify('Transfer code copied')}}><Copy size={15}/> Copy</button></div></label><label className="field"><span>Revocation token (keep private)</span><div className="copy-row"><code>{created.revoke_token||'Token not returned by backend'}</code>{created.revoke_token&&<button className="button secondary" onClick={()=>{navigator.clipboard?.writeText(created.revoke_token);notify('Revocation token copied')}}><Copy size={15}/> Copy</button>}</div></label><p className="muted small">Expires: {fmt(created.expires_at)} · Maximum retrievals: {maxDownloads}</p><button className="text-button" onClick={()=>go('Receive')}>Open recipient screen →</button></div>}
        {banner}</section>}
      {page==='Receive'&&<section className="panel form-panel"><div className="eyebrow">RECIPIENT PORTAL</div><h3>Retrieve a secure transfer</h3><p className="muted">Enter the code from the sender and the passphrase they shared separately.</p><label className="field"><span>Transfer code</span><input value={code} onChange={e=>setCode(e.target.value)} placeholder="Paste transfer code"/></label><label className="field"><span>Decryption method</span><select value="Passphrase" disabled><option>Passphrase</option></select></label><label className="field"><span>Passphrase</span><input type="password" value={receivePass} onChange={e=>setReceivePass(e.target.value)} placeholder="Enter the passphrase"/></label><button className="button primary full" onClick={receive} disabled={loading}>{loading?'Retrieving and decrypting…':'Retrieve and decrypt'}<ArrowUpRight size={17}/></button>{received&&<div className="result-card"><div className="result-head"><Check size={20}/><div><b>Transfer decrypted</b><p>{received.text}</p></div></div>{received.kind==='message'&&<pre className="message-result">{received.text}</pre>}</div>}{banner}</section>}
      {page==='Transfer history'&&<section className="panel"><div className="panel-top"><div><div className="eyebrow">YOUR ACCOUNT</div><h3>My transfers</h3><p className="muted">Transfers created in this browser session. This is not a cross-device account history.</p></div><button className="button secondary" onClick={()=>{setHistory([]);setTransfers([]);notify('Local history cleared')}}><Trash2 size={15}/> Clear local history</button></div>{history.length===0?<div className="empty"><History size={30}/><b>No transfers in this browser yet</b><p>Create a transfer to see it listed here.</p><button className="button secondary" onClick={()=>go('Send securely')}>Create a transfer</button></div>:<div className="table-wrap"><table><thead><tr><th>Transfer</th><th>Created</th><th>Expires</th><th>Limit</th><th>Status</th><th>Action</th></tr></thead><tbody>{history.map(x=><tr key={x.code}><td><b>{x.filename}</b><small>{x.code}</small></td><td>{fmt(x.created_at)}</td><td>{fmt(x.expires_at)}</td><td>{x.max_downloads}</td><td><span className={'status-pill '+(x.revoked?'danger':'')}>{x.revoked?'Revoked':'Created'}</span></td><td><button className="text-button" onClick={()=>revoke(x)} disabled={x.revoked}>Revoke</button></td></tr>)}</tbody></table></div>}{banner}</section>}
      {page==='Key management'&&<section className="panel form-panel"><div className="eyebrow">RECIPIENT KEY MANAGEMENT</div><p className="muted">Generate keys, share public keys, and restore encrypted private-key backups locally. The current file/message transfer flow uses passphrase encryption; these keys are managed separately.</p><h3>Generate a key pair</h3><label className="field"><span>Key exchange algorithm</span><select value={keyAlgo} onChange={e=>setKeyAlgo(e.target.value)}><option>RSA-OAEP (3072-bit)</option><option>ECDH (P-256)</option></select></label><button className="button secondary" onClick={generateKeys}><KeyRound size={16}/> Generate key pair</button>{keys&&<div className="result-card"><b>{keys.algorithm} keys generated locally</b><p className="muted small">The private key remains in this page's memory unless you export an encrypted backup. Never share it.</p><button className="button secondary" onClick={exportPublic}>Export public key JSON</button></div>}<hr/><h3>Import a recipient public key</h3><label className="field"><span>Public-key JSON file</span><input type="file" accept=".json,application/json" onChange={e=>setPubFile(e.target.files?.[0]||null)}/></label><button className="button secondary" onClick={importPublic}>Import public key</button><hr/><h3>Export / restore private-key backup</h3><label className="field"><span>Backup passphrase</span><input type="password" value={backupPass} onChange={e=>setBackupPass(e.target.value)} placeholder="At least 12 characters"/></label><button className="button secondary" onClick={exportBackup}>Export encrypted backup</button><label className="field"><span>Encrypted private-key backup JSON</span><input type="file" accept=".json,application/json" onChange={e=>setBackupFile(e.target.files?.[0]||null)}/></label><button className="button secondary" onClick={restoreBackup}>Unlock backup</button>{banner}</section>}
      {page==='Security activity'&&<section className="panel form-panel"><div className="eyebrow">PROTECTION CENTER</div><h3>Security Activity</h3><p className="muted">Load server-side audit events. Administrator authentication is required. Local events in this tab are shown separately from server audit records.</p><label className="field"><span>Administrator key</span><input type="password" value={adminKey} onChange={e=>setAdminKey(e.target.value)} placeholder="Enter the configured audit admin key"/></label><label className="field"><span>Event type</span><select value={eventType} onChange={e=>setEventType(e.target.value)}><option value="all">All event types</option><option value="transfer_created">Transfer created</option><option value="transfer_retrieved">Transfer retrieved</option><option value="transfer_revoked">Transfer revoked</option><option value="rate_limit_blocked">Rate-limit blocked</option></select></label><label className="field"><span>Search event type or transfer code</span><input value={eventSearch} onChange={e=>setEventSearch(e.target.value)} placeholder="Search audit events…"/></label><button className="button primary full" onClick={loadEvents} disabled={loading}>Load security events</button><div className="event-list">{events.map(e=><div className="event-row" key={e.id||e.at+e.type}><span className="event-icon"><Activity size={16}/></span><div><b>{e.type||'event'}</b><p>{e.detail||e.message||''}</p><small>{fmt(e.at||e.created_at)}</small></div></div>)}{events.length===0&&<p className="muted small">No events loaded. Local actions are recorded only in this browser tab until the server audit API is queried.</p>}</div>{banner}</section>}
      <footer>SecureShare · Secure sharing, thoughtfully designed. <span>Development prototype</span></footer>
    </main>
  </div>;
}
export default App;