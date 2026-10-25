// SentinelScan shared frontend helpers
function toast(msg, kind){
  const t = document.getElementById('toast');
  if(!t) return;
  t.textContent = msg;
  t.className = 'toast show' + (kind ? ' ' + kind : '');
  clearTimeout(t._h);
  t._h = setTimeout(()=>{ t.className = 'toast' + (kind ? ' ' + kind : ''); }, 3200);
}

function toggleRow(id){
  const el = document.getElementById(id);
  if(el) el.style.display = (el.style.display === 'none') ? 'block' : 'none';
}

// auto-dismiss alerts after a few seconds
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('.alert').forEach(function(a){
    setTimeout(function(){ a.style.transition='opacity .4s'; a.style.opacity='0'; }, 6000);
  });
});

// CSRF: attach the double-submit token to same-origin state-changing fetches.
(function(){
  var _fetch = window.fetch;
  function csrfCookie(){
    var m = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : null;
  }
  window.fetch = function(input, init){
    init = init || {};
    var url = (typeof input === 'string') ? input : (input && input.url) || '';
    var method = (init.method || 'GET').toUpperCase();
    if((method === 'POST' || method === 'PUT' || method === 'PATCH')
        && typeof url === 'string' && url.charAt(0) === '/'){
      var tok = csrfCookie();
      if(tok){
        init.headers = Object.assign({}, init.headers);
        init.headers['X-CSRF-Token'] = tok;
      }
    }
    return _fetch(input, init);
  };
})();
