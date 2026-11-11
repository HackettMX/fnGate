(function () {
  'use strict';
  var FG = window.FG;
  var certs = [];
  var overview = { listeners: [], routes: [], states: [] };

  async function loadCerts() {
    try {
      var r = await FG.api('api/cert/list');
      certs = r.certificates || [];
    } catch (e) { certs = []; }
  }

  function certName(id) {
    if (!id) return '自签兜底';
    for (var i = 0; i < certs.length; i++) if (certs[i].id === id) return certs[i].name || certs[i].primary_domain;
    return id.slice(0, 8) + '…（已失效）';
  }

  function certOptions(selected, allowEmpty) {
    var h = allowEmpty ? '<option value="">不指定（使用入口默认 / 自签兜底）</option>' : '<option value="">不指定（自签兜底）</option>';
    certs.forEach(function (c) {
      h += '<option value="' + FG.esc(c.id) + '"' + (selected === c.id ? ' selected' : '') + '>' + FG.esc(c.name || c.primary_domain) + '</option>';
    });
    return h;
  }

  function card(icon, color, bg, label, value, sub) {
    return '<div class="stat-card"><div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + label + '</span><span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }

  function headersText(obj) {
    return Object.keys(obj || {}).map(function (k) { return k + ': ' + obj[k]; }).join('\n');
  }
  function parseHeaders(text) {
    var out = {};
    String(text || '').split('\n').forEach(function (line) {
      var i = line.indexOf(':');
      if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    return out;
  }

  function listenerModal(listener) {
    var l = listener || {};
    var tls = l.tls || {};
    FG.modal({
      title: listener ? '编辑入口' : '新增入口',
      wide: true,
      submitText: '保存入口',
      body: '<div class="form-grid">' +
        '<div class="field"><label for="l-name">名称</label><input type="text" id="l-name" value="' + FG.esc(l.name || '') + '" placeholder="例如：Web 统一入口" /></div>' +
        '<div class="field"><label for="l-port">监听端口</label><input type="number" id="l-port" min="1" max="65535" value="' + (l.port || '') + '" placeholder="如 443 / 8080" /></div>' +
        '<div class="field"><label for="l-proto">协议</label><select id="l-proto">' +
        ['http', 'https', 'tcp'].map(function (p) {
          return '<option value="' + p + '"' + (l.protocol === p ? ' selected' : '') + '>' + p.toUpperCase() + (p === 'tcp' ? '（RDP/SSH/数据库等原始流）' : '') + '</option>';
        }).join('') + '</select></div>' +
        '<div class="field"><label for="l-bind">监听地址</label><input type="text" id="l-bind" value="' + FG.esc(l.bind || '0.0.0.0') + '" placeholder="0.0.0.0" /></div>' +
        '<div class="field full"><label class="checkbox"><input type="checkbox" id="l-enabled" ' + (l.enabled === false ? '' : 'checked') + ' /> 启用该入口</label></div>' +
        '</div><div id="l-tls" style="margin-top:16px;border-top:1px solid var(--line);padding-top:16px">' +
        '<h3 style="font-size:13px;font-weight:600;margin:0 0 12px">HTTPS 与 TLS</h3><div class="form-grid">' +
        '<div class="field"><label for="l-cert">证书</label><select id="l-cert">' + certOptions(tls.cert_id, false) + '</select>' +
        '<span class="hint">在「证书管理」上传或申请后可在此选用</span></div>' +
        '<div class="field"><label for="l-min">最低 TLS 版本</label><select id="l-min">' +
        '<option value="1.2"' + (tls.min_version === '1.3' ? '' : ' selected') + '>TLS 1.2</option>' +
        '<option value="1.3"' + (tls.min_version === '1.3' ? ' selected' : '') + '>TLS 1.3</option></select></div>' +
        '<div class="field"><label class="checkbox"><input type="checkbox" id="l-hsts" ' + (tls.hsts ? 'checked' : '') + ' /> 启用 HSTS</label></div>' +
        '<div class="field"><label class="checkbox"><input type="checkbox" id="l-redirect" ' + (tls.redirect_http ? 'checked' : '') + ' /> HTTP 入口自动跳转 HTTPS</label>' +
        '<span class="hint">对 HTTP 协议入口生效，会 301 到已配置的 HTTPS 入口</span></div>' +
        '</div></div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onOpen: function (mask) {
        function toggle() {
          mask.querySelector('#l-tls').hidden = mask.querySelector('#l-proto').value !== 'https';
        }
        mask.querySelector('#l-proto').addEventListener('change', toggle);
        toggle();
      },
      onSubmit: async function (mask) {
        var port = parseInt(mask.querySelector('#l-port').value, 10);
        if (!port || port < 1 || port > 65535) { FG.fieldError(mask, '请填写合法端口（1-65535）'); return false; }
        var payload = {
          name: mask.querySelector('#l-name').value.trim(),
          port: port,
          protocol: mask.querySelector('#l-proto').value,
          bind: mask.querySelector('#l-bind').value.trim() || '0.0.0.0',
          enabled: mask.querySelector('#l-enabled').checked,
          tls: {
            cert_id: mask.querySelector('#l-cert').value,
            min_version: mask.querySelector('#l-min').value,
            hsts: mask.querySelector('#l-hsts').checked,
            redirect_http: mask.querySelector('#l-redirect').checked,
            alpn: ['h2', 'http/1.1']
          }
        };
        var path = 'api/proxy/listeners';
        if (listener) path += '/' + listener.id;
        await FG.api(path, { method: listener ? 'PUT' : 'POST', body: payload });
        FG.toast('入口已保存', 'ok');
        FG.refresh();
      }
    });
  }

  function routeModal(route, defaultListenerID) {
    var r = route || {};
    var isTcp = false;
    FG.modal({
      title: route ? '编辑路由' : '新增路由',
      wide: true,
      submitText: '保存路由',
      body: '<div class="form-grid">' +
        '<div class="field"><label for="r-listener">所属入口</label><select id="r-listener">' +
        overview.listeners.map(function (l) {
          var id = route ? r.listener_id : (defaultListenerID || l.id);
          return '<option value="' + FG.esc(l.id) + '"' + (id === l.id ? ' selected' : '') + '>' + FG.esc(l.name) + ' · ' + l.port + '/' + l.protocol.toUpperCase() + '</option>';
        }).join('') + '</select></div>' +
        '<div class="field"><label for="r-name">名称</label><input type="text" id="r-name" value="' + FG.esc(r.name || '') + '" placeholder="例如：Emby" /></div>' +
        '<div class="field full"><label for="r-domains">域名（逗号分隔，支持 *.example.com，留空=任意）</label>' +
        '<input type="text" id="r-domains" value="' + FG.esc((r.domains || []).join(', ')) + '" placeholder="emby.example.com, *.example.com" /></div>' +
        '<div class="field"><label for="r-path">路径前缀</label><input type="text" id="r-path" value="' + FG.esc(r.path_prefix || '') + '" placeholder="/emby，留空表示 /" /></div>' +
        '<div class="field"><label for="r-match">匹配方式</label><select id="r-match">' +
        '<option value="prefix"' + (r.match_type === 'exact' ? '' : ' selected') + '>前缀匹配</option>' +
        '<option value="exact"' + (r.match_type === 'exact' ? ' selected' : '') + '>精确匹配</option></select></div>' +
        '<div class="field full"><label for="r-backend">后端地址</label>' +
        '<input type="text" id="r-backend" value="' + FG.esc(r.backend || '') + '" placeholder="http://192.168.1.50:8096 或 10.0.0.5:3389" />' +
        '<span class="hint">HTTP/HTTPS 入口可写 http:// 或 https://；TCP 入口写 主机:端口</span></div>' +
        '<div class="field"><label for="r-timeout">超时（毫秒）</label><input type="number" id="r-timeout" min="1000" max="600000" value="' + (r.timeout_ms || 30000) + '" /></div>' +
        '<div class="field"><label for="r-cert">覆盖证书（可选）</label><select id="r-cert">' + certOptions(r.cert_id, true) + '</select></div>' +
        '<div class="field full"><label>策略</label><div style="display:flex;gap:18px;flex-wrap:wrap">' +
        '<label class="checkbox"><input type="checkbox" id="r-strip" ' + (r.strip_prefix === false ? '' : 'checked') + ' /> 剥离路径前缀</label>' +
        '<label class="checkbox"><input type="checkbox" id="r-ws" ' + (r.websocket === false ? '' : 'checked') + ' /> WebSocket</label>' +
        '<label class="checkbox"><input type="checkbox" id="r-verify" ' + (r.verify_backend_tls ? 'checked' : '') + ' /> 校验后端证书</label>' +
        '<label class="checkbox"><input type="checkbox" id="r-enabled" ' + (r.enabled === false ? '' : 'checked') + ' /> 启用</label>' +
        '</div></div>' +
        '<div class="field full"><label for="r-headers">请求头改写（每行 Key: Value，值为空表示删除该头）</label>' +
        '<textarea id="r-headers" placeholder="X-Frame-Options: SAMEORIGIN">' + FG.esc(headersText(r.request_headers)) + '</textarea></div>' +
        '<div class="field full"><label for="r-desc">备注</label><input type="text" id="r-desc" value="' + FG.esc(r.description || '') + '" /></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onSubmit: async function (mask) {
        var payload = {
          listener_id: mask.querySelector('#r-listener').value,
          name: mask.querySelector('#r-name').value.trim(),
          domains: mask.querySelector('#r-domains').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean),
          path_prefix: mask.querySelector('#r-path').value.trim(),
          match_type: mask.querySelector('#r-match').value,
          backend: mask.querySelector('#r-backend').value.trim(),
          timeout_ms: parseInt(mask.querySelector('#r-timeout').value, 10) || 30000,
          cert_id: mask.querySelector('#r-cert').value,
          strip_prefix: mask.querySelector('#r-strip').checked,
          websocket: mask.querySelector('#r-ws').checked,
          verify_backend_tls: mask.querySelector('#r-verify').checked,
          enabled: mask.querySelector('#r-enabled').checked,
          request_headers: parseHeaders(mask.querySelector('#r-headers').value),
          description: mask.querySelector('#r-desc').value.trim()
        };
        var path = 'api/proxy/routes';
        if (route) path += '/' + route.id;
        await FG.api(path, { method: route ? 'PUT' : 'POST', body: payload });
        FG.toast('路由已保存（不会断开已有连接）', 'ok');
        FG.refresh();
      }
    });
  }

  function stateOf(id) {
    for (var i = 0; i < overview.states.length; i++) if (overview.states[i].id === id) return overview.states[i];
    return null;
  }

  FG.register('proxy', {
    title: '反向代理',
    sub: '入口 + 路由双层模型，HTTP / HTTPS / TCP 统一转发',
    render: async function (root) {
      var results = await Promise.all([
        FG.api('api/proxy/overview'),
        FG.api('api/proxy/status'),
        FG.api('api/cert/list').catch(function () { return { certificates: [] }; })
      ]);
      overview = results[0] || { listeners: [], routes: [], states: [] };
      overview.states = overview.states || [];
      var status = results[1] || {};
      certs = (results[2] || {}).certificates || [];

      var listeners = overview.listeners || [], routes = overview.routes || [];
      var html = '<section class="cards">' +
        card('⇥', '#2f6fed', '#e9f0ff', '入口', listeners.length, '按端口监听') +
        card('⇄', '#7c3aed', '#f1eafe', '路由', routes.length, '按域名 + 路径分流') +
        card('◉', '#16a34a', '#e8f7ed', '健康后端', status.healthy || 0, 'TCP 连通探测') +
        card('!', (status.failed || 0) > 0 ? '#dc2626' : '#16a34a', (status.failed || 0) > 0 ? '#fdecec' : '#e8f7ed',
          '未生效', status.failed || 0, '端口占用或权限问题') +
        '</section>';

      if (status.can_bind_low === false) {
        html += '<div class="notice"><span class="notice-icon">!</span><div class="notice-body"><strong>当前无法绑定 1024 以下端口</strong>' +
          '<p>80 / 443 需要 cap_net_bind_service。请重启应用让启动脚本授权，或改用高位端口配合路由器端口转发。</p></div></div>';
      }

      html += '<section class="panel"><div class="panel-head"><div><h2>监听入口 <span class="count-badge">' + listeners.length +
        '</span></h2><p>一个端口一个入口，其下可挂多条域名 / 路径路由</p></div><div class="panel-actions">' +
        '<button type="button" class="btn" data-act="apply">重新应用</button>' +
        '<button type="button" class="btn" data-act="logs">访问日志</button>' +
        '<button type="button" class="btn" data-act="add-route"' + (listeners.length ? '' : ' disabled') + '>+ 新增路由</button>' +
        '<button type="button" class="btn btn-primary" data-act="add-listener">+ 新增入口</button>' +
        '</div></div><div class="panel-body" style="padding:0">';

      if (!listeners.length) {
        html += FG.empty('还没有监听入口', '先「新增入口」指定端口与协议，再为其添加路由规则');
      } else {
        listeners.forEach(function (l) {
          var st = stateOf(l.id) || {};
          var lroutes = routes.filter(function (r) { return r.listener_id === l.id; });
          html += '<div style="padding:16px 18px;border-bottom:1px solid var(--line)">' +
            '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
            '<span class="dot ' + (st.active ? 'dot-on' : 'dot-off') + '"></span>' +
            '<strong style="font-size:14px">' + FG.esc(l.name) + '</strong>' +
            FG.badge(String(l.protocol).toUpperCase(), l.protocol === 'https' ? 'tag-purple' : (l.protocol === 'tcp' ? 'tag-amber' : 'tag-blue')) +
            '<span class="mono muted">' + l.port + '</span>' +
            '<span class="count-badge">' + lroutes.length + ' 条路由</span>' +
            (l.protocol === 'https' ? '<span class="muted" style="font-size:12px">证书：' + FG.esc(certName(l.tls && l.tls.cert_id)) + '</span>' : '') +
            '<span style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">' +
            '<button type="button" class="btn btn-sm" data-add-route="' + FG.esc(l.id) + '">+ 路由</button>' +
            '<button type="button" class="btn btn-sm" data-edit-listener="' + FG.esc(l.id) + '">编辑</button>' +
            '<button type="button" class="btn btn-sm" data-toggle-listener="' + FG.esc(l.id) + '">' + (l.enabled ? '停用' : '启用') + '</button>' +
            '<button type="button" class="btn btn-sm btn-danger" data-del-listener="' + FG.esc(l.id) + '">删除</button>' +
            '</span></div>';
          if (st.error) html += '<div class="notice danger" style="margin:10px 0 0"><span class="notice-icon">!</span><div class="notice-body"><p>' + FG.esc(st.error) + '</p></div></div>';
          if (!lroutes.length) {
            html += '<p class="muted" style="margin:10px 0 0;font-size:12.5px">该入口还没有路由，访问会返回 404。</p>';
          } else {
            html += '<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>状态</th><th>名称</th><th>域名</th><th>路径</th><th>后端</th><th>策略</th><th>操作</th></tr></thead><tbody>';
            lroutes.forEach(function (r) {
              html += '<tr><td><span class="dot ' + (r.enabled ? 'dot-on' : 'dot-idle') + '"></span></td>' +
                '<td>' + FG.esc(r.name || '-') + '</td>' +
                '<td>' + (r.domains && r.domains.length ? r.domains.map(function (d) { return FG.esc(d); }).join('<br>') : '<span class="muted">任意</span>') + '</td>' +
                '<td class="mono">' + FG.esc(r.path_prefix || '/') + (r.match_type === 'exact' ? ' <span class="muted">(精确)</span>' : '') + '</td>' +
                '<td class="mono">' + FG.esc(r.backend) + '</td>' +
                '<td class="muted" style="font-size:12px">' + (r.strip_prefix && r.path_prefix ? '剥前缀 · ' : '') + (r.websocket ? 'WS' : '无 WS') + (r.cert_id ? ' · 独立证书' : '') + '</td>' +
                '<td><span class="link" data-edit-route="' + FG.esc(r.id) + '">编辑</span>' +
                '<span class="link" data-toggle-route="' + FG.esc(r.id) + '">' + (r.enabled ? '停用' : '启用') + '</span>' +
                '<span class="link danger" data-del-route="' + FG.esc(r.id) + '">删除</span></td></tr>';
            });
            html += '</tbody></table></div>';
          }
          html += '</div>';
        });
      }
      html += '</div></section>';
      html += '<p class="hint" style="color:var(--text-3);font-size:12px">功能边界：内置 HTTP→HTTPS 跳转、HSTS、请求头改写、访问日志；' +
        '不提供访问控制、限流 / WAF、缓存与多后端负载均衡。修改路由不会重建监听，已有连接保持不断。</p>';
      root.innerHTML = html;

      root.onclick = async function (e) {
        var t = e.target;
        function attr(name) { return t.getAttribute && t.getAttribute(name); }
        function findListener(id) { for (var i = 0; i < listeners.length; i++) if (listeners[i].id === id) return listeners[i]; return null; }
        function findRoute(id) { for (var i = 0; i < routes.length; i++) if (routes[i].id === id) return routes[i]; return null; }
        try {
          if (attr('data-act') === 'add-listener') { listenerModal(null); }
          else if (attr('data-act') === 'add-route') { routeModal(null); }
          else if (attr('data-add-route')) { routeModal(null, attr('data-add-route')); }
          else if (attr('data-act') === 'apply') {
            var a = await FG.api('api/proxy/apply', { method: 'POST' });
            FG.toast('已重新应用 ' + ((a.listeners || []).length) + ' 个入口', 'ok'); FG.refresh();
          } else if (attr('data-act') === 'logs') {
            var lg = await FG.api('api/proxy/logs?n=200');
            FG.modal({
              title: '访问日志（最近 200 行）', wide: true, readOnly: true,
              body: '<div class="code-box">' + FG.esc((lg.lines || []).join('\n') || '暂无访问记录') + '</div>'
            });
          } else if (attr('data-edit-listener')) { listenerModal(findListener(attr('data-edit-listener'))); }
          else if (attr('data-edit-route')) { routeModal(findRoute(attr('data-edit-route'))); }
          else if (attr('data-toggle-listener')) {
            var l = findListener(attr('data-toggle-listener'));
            if (!l) return;
            l.enabled = !l.enabled;
            await FG.api('api/proxy/listeners/' + l.id, { method: 'PUT', body: l });
            FG.toast(l.enabled ? '入口已启用' : '入口已停用', 'ok'); FG.refresh();
          } else if (attr('data-toggle-route')) {
            var rt = findRoute(attr('data-toggle-route'));
            if (!rt) return;
            rt.enabled = !rt.enabled;
            await FG.api('api/proxy/routes/' + rt.id, { method: 'PUT', body: rt });
            FG.toast(rt.enabled ? '路由已启用' : '路由已停用', 'ok'); FG.refresh();
          } else if (attr('data-del-listener')) {
            if (!await FG.confirmBox('删除入口会一并删除其下所有路由，确认继续？', '删除入口')) return;
            var d = await FG.api('api/proxy/listeners/' + attr('data-del-listener'), { method: 'DELETE' });
            FG.toast(d.note || '入口已删除', 'ok'); FG.refresh();
          } else if (attr('data-del-route')) {
            if (!await FG.confirmBox('确认删除这条路由？', '删除路由')) return;
            await FG.api('api/proxy/routes/' + attr('data-del-route'), { method: 'DELETE' });
            FG.toast('路由已删除', 'ok'); FG.refresh();
          }
        } catch (err) { FG.toast(err.message, 'err'); }
      };
    }
  });
})();
