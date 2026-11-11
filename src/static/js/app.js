(function () {
  'use strict';

  var CSRF = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  var pages = {};
  var current = 'overview';
  var pageEl = null;

  async function api(path, opts) {
    opts = opts || {};
    var rel = String(path).replace(/^\/+/, '');
    var method = (opts.method || 'GET').toUpperCase();
    var headers = Object.assign({}, opts.headers || {});
    var body = opts.body;
    if (body !== undefined && typeof body !== 'string') {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    } else if (body !== undefined && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(method) >= 0) {
      headers['X-CSRF-Token'] = CSRF;
    }
    var res = await fetch(rel, {
      method: method, headers: headers, body: body,
      credentials: 'same-origin', cache: 'no-store'
    });
    var data = {};
    try { data = await res.json(); } catch (e) { /* 非 JSON 响应 */ }
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data && Object.prototype.hasOwnProperty.call(data, 'data') ? data.data : data;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function toast(msg, kind) {
    var root = document.getElementById('toast-root');
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(function () { el.remove(); }, 3000);
  }

  function modal(cfg) {
    var root = document.getElementById('modal-root');
    var mask = document.createElement('div');
    mask.className = 'modal-mask';
    mask.innerHTML = '<div class="modal' + (cfg.wide ? ' wide' : '') + '">' +
      '<div class="modal-head"><h3>' + esc(cfg.title || '') + '</h3><button type="button" class="icon-btn" data-close>&times;</button></div>' +
      '<div class="modal-body">' + (cfg.body || '') + '</div>' +
      '<div class="modal-foot"><span class="foot-hint">' + esc(cfg.hint || '') + '</span>' +
      '<button type="button" class="btn" data-close>取消</button>' +
      (cfg.readOnly ? '' : '<button type="button" class="btn btn-primary" data-submit>' + esc(cfg.submitText || '保存') + '</button>') +
      '</div></div>';
    root.appendChild(mask);
    function close() { mask.remove(); }
    mask.querySelectorAll('[data-close]').forEach(function (b) { b.addEventListener('click', close); });
    mask.addEventListener('click', function (e) { if (e.target === mask) close(); });
    var submit = mask.querySelector('[data-submit]');
    if (submit) {
      submit.addEventListener('click', async function () {
        submit.disabled = true;
        try {
          var done = await cfg.onSubmit(mask, close);
          if (done !== false) close();
        } catch (e) {
          toast(e.message || String(e), 'err');
        } finally {
          submit.disabled = false;
        }
      });
    }
    if (cfg.onOpen) cfg.onOpen(mask, close);
    return close;
  }

  function confirmBox(message, title) {
    return new Promise(function (resolve) {
      var root = document.getElementById('modal-root');
      var mask = document.createElement('div');
      mask.className = 'modal-mask';
      mask.innerHTML = '<div class="modal" style="width:min(430px,100%)">' +
        '<div class="modal-head"><h3>' + esc(title || '请确认') + '</h3></div>' +
        '<div class="modal-body" style="font-size:13.5px;line-height:1.7">' + esc(message) + '</div>' +
        '<div class="modal-foot"><button type="button" class="btn" data-no>取消</button>' +
        '<button type="button" class="btn btn-danger" data-yes>确认</button></div></div>';
      root.appendChild(mask);
      function done(v) { mask.remove(); resolve(v); }
      mask.querySelector('[data-no]').addEventListener('click', function () { done(false); });
      mask.querySelector('[data-yes]').addEventListener('click', function () { done(true); });
      mask.addEventListener('click', function (e) { if (e.target === mask) done(false); });
    });
  }

  function fmtDate(s) {
    if (!s) return '-';
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(s);
    return d.toLocaleString('zh-CN', { hour12: false });
  }
  function daysUntil(s) {
    if (!s) return null;
    var d = new Date(s);
    if (isNaN(d.getTime())) return null;
    return Math.ceil((d.getTime() - Date.now()) / 86400000);
  }
  function expiryClass(days) {
    if (days == null) return 'tag';
    if (days < 0) return 'tag tag-red';
    if (days <= 15) return 'tag tag-red';
    if (days <= 30) return 'tag tag-amber';
    return 'tag tag-green';
  }
  function badge(text, kind) { return '<span class="tag ' + (kind || '') + '">' + esc(text) + '</span>'; }
  function empty(title, sub) {
    return '<div class="empty"><strong>' + esc(title) + '</strong>' + esc(sub || '') + '</div>';
  }
  function fieldError(mask, msg) {
    var el = mask.querySelector('.modal-error');
    if (el) { el.textContent = msg; el.hidden = !msg; }
  }

  function register(name, def) { pages[name] = def; }

  async function show(name) {
    if (!pages[name]) name = 'overview';
    current = name;
    var def = pages[name];
    document.getElementById('page-title').textContent = def.title || name;
    document.getElementById('page-sub').textContent = def.sub || '';
    document.querySelectorAll('.nav-item').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-page') === name);
    });
    if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
    pageEl = document.getElementById('page');
    pageEl.innerHTML = '<div class="panel"><div class="empty"><span class="spinner"></span> 正在加载…</div></div>';
    try {
      await def.render(pageEl);
      await updateStatus();
    } catch (e) {
      pageEl.innerHTML = '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body"><strong>加载失败</strong><p>' + esc(e.message) + '</p></div></div>';
    }
  }

  async function updateStatus() {
    try {
      var s = await api('api/system/status');
      var dot = document.getElementById('side-dot');
      dot.className = 'dot dot-on';
      document.getElementById('side-status').textContent = '运行中';
      var pill = document.getElementById('perm-pill');
      pill.hidden = s.can_bind_low !== false;
      if (s.can_bind_low === false) {
        pill.title = '当前以 ' + (s.run_user || '未知用户') + ' 运行且缺少 cap_net_bind_service，80/443 等低端口规则无法生效';
      }
    } catch (e) {
      document.getElementById('side-dot').className = 'dot dot-off';
      document.getElementById('side-status').textContent = '连接失败';
    }
  }

  async function refresh() {
    var def = pages[current];
    if (!def || !pageEl) return;
    try {
      await (def.poll || def.render)(pageEl);
      await updateStatus();
    } catch (e) { /* 轮询失败不打断界面 */ }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('nav').addEventListener('click', function (e) {
      var btn = e.target.closest('.nav-item');
      if (btn) show(btn.getAttribute('data-page'));
    });
    document.getElementById('btn-refresh').addEventListener('click', function () { refresh(); toast('已刷新', 'ok'); });
    window.addEventListener('hashchange', function () { show(location.hash.slice(1)); });
    show(location.hash.slice(1) || 'overview');
    setInterval(refresh, 15000);
  });

  window.FG = {
    api: api, esc: esc, toast: toast, modal: modal, confirmBox: confirmBox,
    fmtDate: fmtDate, daysUntil: daysUntil, expiryClass: expiryClass,
    badge: badge, empty: empty, fieldError: fieldError,
    register: register, show: show, refresh: refresh,
    current: function () { return current; }, csrf: CSRF
  };
})();
