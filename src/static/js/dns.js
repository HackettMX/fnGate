(function () {
  'use strict';
  var FG = window.FG;
  var data = { providers: [] };
  var specs = [];

  // 解析查询/体检的页面级状态：切页或刷新后仍保留上一次结果。
  var rq = {
    servers: [],        // [{server, label, on}]
    types: ['A', 'AAAA', 'CNAME', 'TXT', 'NS', 'SOA', 'MX', 'CAA'],
    qtype: 'A',
    follow: true,
    name: '',
    lastQuery: null,
    lastDiagnose: null
  };

  var statusMeta = {
    pass: { cls: 'tag-green', text: '通过', ico: '✓' },
    warn: { cls: 'tag-amber', text: '注意', ico: '!' },
    fail: { cls: 'tag-red', text: '失败', ico: '✗' },
    skip: { cls: '', text: '跳过', ico: '–' }
  };

  function card(icon, color, bg, label, value, sub) {
    return '<div class="stat-card"><div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + label + '</span><span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }

  function find(id) {
    for (var i = 0; i < data.providers.length; i++) if (data.providers[i].id === id) return data.providers[i];
    return null;
  }

  function typeBadge(p) {
    var kind = p.type === 'manual' ? 'tag-amber' : 'tag-blue';
    return FG.badge(p.type_name || p.type, kind);
  }

  // 状态点：手动模式没有凭据可测；有 LastCheckAt 才判断是否异常。
  function statusCell(p) {
    if (p.type === 'manual') return FG.badge('无需凭据', '');
    if (!p.last_check_at) return FG.badge('未校验', '');
    if (p.last_check_ok) {
      return FG.badge('正常', 'tag-green') + '<br><span class="muted" style="font-size:11.5px">' + FG.esc(p.last_check_at) + '</span>';
    }
    return '<span title="' + FG.esc(p.last_check_msg || '') + '">' + FG.badge('异常', 'tag-red') +
      '</span><br><span class="muted" style="font-size:11.5px;max-width:190px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom">' +
      FG.esc(p.last_check_msg || '') + '</span>';
  }

  function zoneCell(p) {
    if (p.type === 'manual') return '<span class="muted">—</span>';
    var n = p.zone_count > 0 ? p.zone_count + ' 个' : '<span class="muted">未读取</span>';
    return n + '<br><span class="link" data-zones="' + FG.esc(p.id) + '" style="font-size:12px">查看域名</span>';
  }

  // ---------- 解析查询：服务器选择 ----------

  function buildServers(res) {
    var list = [], index = {};
    var selected = res.selected || [];
    function push(server, label, on) {
      if (!server) return;
      if (index[server]) { if (on) index[server].on = true; return; }
      var item = { server: server, label: label || server, on: !!on };
      index[server] = item;
      list.push(item);
    }
    (res.system || []).forEach(function (s) { push(s, '系统 DNS', selected.indexOf(s) >= 0); });
    (res.presets || []).forEach(function (p) { push(p.server, p.label, selected.indexOf(p.server) >= 0); });
    (res.custom || []).forEach(function (s) { push(s, '自定义 ' + s, true); });
    return list;
  }

  function chips() {
    if (!rq.servers.length) return '<span class="muted">没有可用的 DNS 服务器</span>';
    return rq.servers.map(function (s) {
      return '<button type="button" class="chip' + (s.on ? ' on' : '') + '" data-srv="' + FG.esc(s.server) + '">' +
        FG.esc(s.label) + '<span class="chip-addr">' + FG.esc(s.server) + '</span></button>';
    }).join('');
  }

  function selectedServers() {
    return rq.servers.filter(function (s) { return s.on; }).map(function (s) { return s.server; });
  }

  function rcodeBadge(r) {
    if (r.error) return FG.badge('无响应', 'tag-red');
    if (r.rcode === 'NOERROR') return FG.badge('NOERROR', 'tag-green');
    if (r.rcode === 'NXDOMAIN') return FG.badge('NXDOMAIN', 'tag-amber');
    return FG.badge(r.rcode || '?', 'tag-red');
  }

  function renderQuery() {
    var el = document.getElementById('rq-result');
    if (!el) return;
    var r = rq.lastQuery;
    if (!r) {
      el.innerHTML = '<section class="panel"><div class="panel-body">' +
        FG.empty('还没有查询结果', '输入域名后点「查询记录」，会同时向所有勾选的 DNS 发起查询并排对比') +
        '</div></section>';
      return;
    }

    var head = '<section class="panel"><div class="panel-head"><div><h2>' + FG.esc(r.name) +
      ' <span class="count-badge">' + FG.esc(r.type) + '</span></h2><p>' +
      FG.esc(r.summary) + ' · 耗时 ' + r.elapsed_ms + ' ms</p></div>' +
      '<div class="panel-actions">' + (r.consistent ? FG.badge('结果一致', 'tag-green') : FG.badge('存在差异', 'tag-amber')) +
      '</div></div><div class="panel-body" style="padding:0">';

    var chain = '';
    if (r.chain && r.chain.length) {
      chain = '<div class="resolve-chain">CNAME 链：' +
        r.chain.map(function (n) { return '<span class="chain-node">' + FG.esc(n) + '</span>'; }).join('<span class="chain-arrow">→</span>') +
        '</div>';
    }

    var rows = r.results.map(function (x) {
      var answers = (x.answers || []).length
        ? x.answers.map(function (a) { return '<div class="mono ans">' + FG.esc(a) + '</div>'; }).join('')
        : '<span class="muted">' + (x.error ? '—' : '空（无该类型记录）') + '</span>';
      var auth = (x.authority || []).length
        ? '<div class="muted mono" style="font-size:11.5px;margin-top:4px">authority: ' + FG.esc(x.authority[0]) + '</div>'
        : '';
      return '<tr><td class="mono" style="font-size:12px;white-space:nowrap">' + FG.esc(x.server) + '</td>' +
        '<td>' + rcodeBadge(x) + (x.truncated ? '<br><span class="muted" style="font-size:11px">已截断重试</span>' : '') + '</td>' +
        '<td>' + answers + auth + (x.error ? '<div class="muted" style="font-size:11.5px;color:#dc2626">' + FG.esc(x.error) + '</div>' : '') + '</td>' +
        '<td class="muted" style="font-size:12px;white-space:nowrap">' + x.elapsed_ms + ' ms</td></tr>';
    }).join('');

    el.innerHTML = head + chain +
      '<div class="table-wrap"><table><thead><tr><th>服务器</th><th>响应码</th><th>答案</th><th>耗时</th></tr></thead><tbody>' +
      rows + '</tbody></table></div></div></section>';
  }

  function renderDiagnose() {
    var el = document.getElementById('rq-diagnose');
    if (!el) return;
    var d = rq.lastDiagnose;
    if (!d) { el.innerHTML = ''; return; }

    var tone = d.fail_count > 0 ? 'danger' : (d.warn_count > 0 ? 'warn' : 'ok');
    var icon = d.fail_count > 0 ? '!' : (d.warn_count > 0 ? 'i' : '✓');
    var noticeCls = tone === 'danger' ? 'notice danger' : (tone === 'warn' ? 'notice' : 'notice ok');

    var checks = d.checks.map(function (c) {
      var meta = statusMeta[c.status] || statusMeta.skip;
      return '<div class="check-row check-' + c.status + '">' +
        '<span class="check-ico">' + meta.ico + '</span>' +
        '<div class="check-body"><div class="check-title"><strong>' + FG.esc(c.name) + '</strong>' +
        FG.badge(meta.text, meta.cls) + '</div>' +
        '<p>' + FG.esc(c.detail || '') + '</p>' +
        (c.advice ? '<p class="check-advice">建议：' + FG.esc(c.advice) + '</p>' : '') +
        '</div></div>';
    }).join('');

    el.innerHTML = '<section class="panel"><div class="panel-head"><div><h2>域名体检 <span class="count-badge">' +
      FG.esc(d.domain) + '</span></h2><p>区域 ' + FG.esc(d.zone || '未知') +
      (d.nameservers && d.nameservers.length ? ' · 权威 NS：' + FG.esc(d.nameservers.join('、')) : '') +
      ' · 耗时 ' + d.elapsed_ms + ' ms</p></div>' +
      '<div class="panel-actions">' + FG.badge('通过 ' + d.pass_count, 'tag-green') +
      (d.warn_count ? FG.badge('注意 ' + d.warn_count, 'tag-amber') : '') +
      (d.fail_count ? FG.badge('失败 ' + d.fail_count, 'tag-red') : '') + '</div></div>' +
      '<div class="panel-body">' +
      '<div class="' + noticeCls + '"><span class="notice-icon">' + icon + '</span><div class="notice-body">' +
      '<strong>' + FG.esc(d.verdict) + '</strong></div></div>' +
      '<div class="check-list">' + checks + '</div>' +
      '</div></section>';
  }

  // ---------- 添加 / 编辑弹窗 ----------

  function providerModal(existing) {
    var isEdit = !!existing;
    var type = isEdit ? existing.type : (specs.length ? specs[0].type : 'manual');

    function specOf(t) {
      for (var i = 0; i < specs.length; i++) if (specs[i].type === t) return specs[i];
      return null;
    }
    function currentSpec(mask) { return specOf(mask.querySelector('#p-type').value); }
    function collectFields(mask) {
      var fields = {};
      mask.querySelectorAll('#p-fields [data-key]').forEach(function (el) {
        var v = el.value.trim();
        if (v !== '') fields[el.getAttribute('data-key')] = v;
      });
      return fields;
    }

    var opts = specs.map(function (s) {
      var sel = s.type === type ? ' selected' : '';
      return '<option value="' + s.type + '"' + sel + '>' + FG.esc(s.name) + '</option>';
    }).join('');

    FG.modal({
      title: isEdit ? '编辑 DNS 服务商' : '添加 DNS 服务商',
      wide: true, submitText: isEdit ? '保存修改' : '保存',
      hint: isEdit
        ? '只填需要修改的凭据字段；全部留空表示沿用现有凭据'
        : '凭据只写入应用私有目录（0600），不会出现在配置备份或 API 响应中',
      body: '<div class="form-grid">' +
        '<div class="field"><label for="p-type">类型</label><select id="p-type"' + (isEdit ? ' disabled' : '') + '>' + opts + '</select></div>' +
        '<div class="field"><label for="p-name">显示名称</label><input type="text" id="p-name" placeholder="留空使用默认名称" value="' +
          FG.esc(isEdit ? existing.name : '') + '" /></div>' +
        '<div class="field full"><p class="hint" id="p-hint" style="color:var(--text-3);font-size:12px"></p></div>' +
        '<div class="field full" id="p-fields"></div>' +
        '<div class="field full" id="p-verify-row">' +
          '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
            '<button type="button" class="btn" id="p-verify">测试连接</button>' +
            '<span id="p-verify-msg" style="font-size:12.5px;color:var(--text-3);line-height:1.5"></span>' +
          '</div>' +
          '<p class="hint" style="color:var(--text-3);font-size:12px;margin-top:6px">用只读接口验证凭据（列域名 / 列 Zone），不会创建或修改任何 DNS 记录</p>' +
        '</div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onOpen: function (mask) {
        function render() {
          var spec = currentSpec(mask);
          mask.querySelector('#p-hint').textContent = spec ? spec.hint : '';
          var h = '';
          (spec ? spec.fields : []).forEach(function (f) {
            var ph = isEdit && f.required ? '留空则保持不变' : f.placeholder;
            h += '<div class="field"><label for="pf-' + f.key + '">' + FG.esc(f.label) +
              (f.required && !isEdit ? ' <span style="color:#dc2626">*</span>' : '') + '</label>' +
              '<input type="' + (f.secret ? 'password' : 'text') + '" id="pf-' + f.key + '" data-key="' + f.key +
              '" placeholder="' + FG.esc(ph) + '" autocomplete="off" /></div>';
          });
          mask.querySelector('#p-fields').innerHTML = h
            ? '<div class="form-grid">' + h + '</div>'
            : '<p class="muted">手动模式无需填写任何凭据。</p>';
          mask.querySelector('#p-verify-row').style.display = (spec && spec.type === 'manual') ? 'none' : '';
          var msg = mask.querySelector('#p-verify-msg');
          msg.textContent = ''; msg.style.color = 'var(--text-3)';
        }
        if (!isEdit) mask.querySelector('#p-type').addEventListener('change', render);
        mask.querySelector('#p-verify').addEventListener('click', async function () {
          var btn = this;
          var msg = mask.querySelector('#p-verify-msg');
          btn.disabled = true;
          msg.textContent = '正在测试连接…';
          msg.style.color = 'var(--text-3)';
          try {
            var res = await FG.api('api/dns/providers/verify', {
              method: 'POST',
              body: { type: mask.querySelector('#p-type').value, fields: collectFields(mask) }
            });
            msg.textContent = '✓ ' + ((res && res.message) || '连接正常');
            msg.style.color = '#16a34a';
          } catch (e) {
            msg.textContent = '✗ ' + (e.message || '连接失败');
            msg.style.color = '#dc2626';
          } finally {
            btn.disabled = false;
          }
        });
        render();
      },
      onSubmit: async function (mask) {
        var btn = mask.querySelector('[data-submit]');
        var original = btn ? btn.textContent : '';
        var payload = {
          type: mask.querySelector('#p-type').value,
          name: mask.querySelector('#p-name').value.trim(),
          fields: collectFields(mask)
        };
        if (isEdit && !Object.keys(payload.fields).length) delete payload.fields;
        FG.fieldError(mask, '');
        // 保存时后端也会跑同一套只读校验，这里同步提示，避免用户以为界面卡住
        if (btn) btn.textContent = '正在测试…';
        try {
          if (isEdit) {
            await FG.api('api/dns/providers/' + existing.id, { method: 'PUT', body: { name: payload.name, fields: payload.fields || {} } });
          } else {
            await FG.api('api/dns/providers', { method: 'POST', body: payload });
          }
        } catch (e) {
          FG.fieldError(mask, e.message || '保存失败');
          return false;
        } finally {
          if (btn) btn.textContent = original;
        }
        FG.toast(isEdit ? '服务商已更新' : 'DNS 服务商已保存', 'ok');
        FG.refresh();
      }
    });
  }

  function zonesModal(p) {
    FG.modal({
      title: '可管理域名 · ' + p.name, wide: true, readOnly: true,
      body: '<div id="zones-body"><div class="empty"><span class="spinner"></span> 正在读取…</div></div>'
    });
    FG.api('api/dns/providers/' + p.id + '/zones').then(function (res) {
      var el = document.getElementById('zones-body');
      if (!el) return;
      var zones = (res && res.zones) || [];
      if (!zones.length) {
        el.innerHTML = FG.empty('该账号下没有域名', '请先在 DNS 控制台添加解析域名，否则签发时无法匹配到 zone');
        return;
      }
      el.innerHTML = '<p class="hint" style="margin-bottom:10px;font-size:12px">共 ' + zones.length +
        ' 个域名，DNS 凭据已通过只读校验；签发时订单域名必须落在其中之一。</p>' +
        '<div class="table-wrap" style="max-height:360px;overflow:auto"><table><thead><tr><th>域名</th><th>操作</th></tr></thead><tbody>' +
        zones.map(function (z) {
          return '<tr><td class="mono">' + FG.esc(z) + '</td>' +
            '<td><span class="link" data-new-order="' + FG.esc(z) + '">用此域名申请证书</span></td></tr>';
        }).join('') + '</tbody></table></div>';
      el.onclick = function (e) {
        var z = e.target.getAttribute && e.target.getAttribute('data-new-order');
        if (z && FG.orderModal) FG.orderModal({ domains: z + ', *.' + z });
      };
    }).catch(function (e) {
      var el = document.getElementById('zones-body');
      if (el) el.innerHTML = '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body"><strong>读取失败</strong><p>' + FG.esc(e.message) + '</p></div></div>';
    });
  }

  // ---------- 页面 ----------

  FG.register('dns', {
    title: '域名解析',
    sub: '解析查询与签发前体检，以及 DNSPod / 阿里云 / Cloudflare 凭据管理',
    render: async function (root) {
      var res = await Promise.all([
        FG.api('api/dns/providers'),
        FG.api('api/dns/types').catch(function () { return { types: [] }; }),
        rq.servers.length ? Promise.resolve(null) : FG.api('api/dns/resolvers').catch(function () { return null; })
      ]);
      data = res[0] || data;
      specs = (res[1] && res[1].types) || specs;
      if (res[2]) {
        rq.servers = buildServers(res[2]);
        rq.types = res[2].types || rq.types;
      }

      var providers = data.providers || [];
      var ok = providers.filter(function (p) { return p.last_check_ok; }).length;
      var bad = providers.filter(function (p) { return p.last_check_at && !p.last_check_ok; }).length;
      var zones = providers.reduce(function (n, p) { return n + (p.zone_count || 0); }, 0);

      var html = '<section class="cards">' +
        card('◇', '#7c3aed', '#f1eafe', '服务商', providers.length, '同类型可添加多个账号') +
        card('✓', '#16a34a', '#e8f7ed', '校验通过', ok, '最近一次只读探测结果') +
        card('!', bad ? '#dc2626' : '#16a34a', bad ? '#fdecec' : '#e8f7ed', '校验异常', bad, bad ? '点「测试连接」重试' : '暂无异常') +
        card('▤', '#2f6fed', '#e9f0ff', '可管理域名', zones, '已读取到的域名总数') +
        '</section>';

      if (!providers.length) {
        html += '<div class="notice"><span class="notice-icon">i</span><div class="notice-body">' +
          '<strong>还没有 DNS 服务商</strong><p>添加后即可申请泛域名证书并自动续期；若只是先试用，可选「手动添加 TXT 记录」，不需要任何 API 凭据。</p></div></div>';
      }

      html += '<section class="panel"><div class="panel-head"><div><h2>DNS 服务商 <span class="count-badge">' + providers.length +
        '</span></h2><p>凭据保存在应用私有目录，不随配置备份导出；测试连接只调用只读接口</p></div>' +
        '<div class="panel-actions"><button type="button" class="btn btn-primary" data-act="add">+ 添加服务商</button></div></div>' +
        '<div class="panel-body" style="padding:0">';

      if (!providers.length) {
        html += FG.empty('尚未配置 DNS 服务商', '可添加「手动添加 TXT 记录」先试用，无需任何 API 凭据');
      } else {
        html += '<div class="table-wrap"><table><thead><tr>' +
          '<th>名称 / 类型</th><th>账号</th><th>状态</th><th>可管理域名</th><th>引用</th><th>操作</th>' +
          '</tr></thead><tbody>';
        providers.forEach(function (p) {
          var refs = [];
          if (p.cert_count) refs.push(p.cert_count + ' 张证书');
          if (p.order_count) refs.push(p.order_count + ' 个任务');
          html += '<tr><td><strong>' + FG.esc(p.name) + '</strong><br>' + typeBadge(p) + '</td>' +
            '<td class="mono" style="font-size:12px">' + (p.account_hint ? FG.esc(p.account_hint) : '<span class="muted">—</span>') + '</td>' +
            '<td>' + statusCell(p) + '</td>' +
            '<td>' + zoneCell(p) + '</td>' +
            '<td style="font-size:12px">' + (refs.length ? refs.join('<br>') : '<span class="muted">未使用</span>') + '</td>' +
            '<td style="white-space:nowrap">' +
            (p.type === 'manual' ? '' : '<span class="link" data-test="' + FG.esc(p.id) + '">测试连接</span>') +
            '<span class="link" data-edit="' + FG.esc(p.id) + '">编辑</span>' +
            '<span class="link danger" data-del="' + FG.esc(p.id) + '">删除</span>' +
            '</td></tr>';
        });
        html += '</tbody></table></div>';
      }
      html += '</div></section>';

      html += '<p class="hint" style="color:var(--text-3);font-size:12px">' +
        'DNS 服务商被证书用于自动续期时不可删除；如需更换，请先在「证书申请」里切换服务商。' +
        '「查看域名」读取的是该账号下真实存在的解析域名，签发前可据此确认域名是否已托管。</p>';

      // ---- 解析查询 ----
      html += '<section class="panel"><div class="panel-head"><div><h2>解析查询</h2>' +
        '<p>同时向多台 DNS 发起同一查询，用于判断记录是否写对、是否已经传播</p></div></div>' +
        '<div class="panel-body">' +
        '<div class="resolve-form">' +
        '<input type="text" id="rq-name" placeholder="example.com 或 _acme-challenge.example.com" value="' + FG.esc(rq.name) + '" />' +
        '<select id="rq-type">' + rq.types.map(function (t) {
          return '<option value="' + t + '"' + (rq.qtype === t ? ' selected' : '') + '>' + t + '</option>';
        }).join('') + '</select>' +
        '<button type="button" class="btn btn-primary" data-act="query">查询记录</button>' +
        '<button type="button" class="btn" data-act="diagnose">一键体检</button>' +
        '<label class="checkbox" style="white-space:nowrap"><input type="checkbox" id="rq-follow"' +
          (rq.follow ? ' checked' : '') + ' /> 跟随 CNAME</label>' +
        '</div>' +
        '<div class="resolve-servers"><span class="resolve-label">DNS 服务器</span><div class="chips" id="rq-servers">' +
        chips() + '</div></div>' +
        '<p class="hint" style="color:var(--text-3);font-size:12px;margin-top:8px">' +
        '默认使用设置里的服务器（系统 DNS + 国内公共 DNS）。查询只发出 DNS 请求，不会创建或修改任何记录。' +
        '签发失败时，对报错域名点「一键体检」可查清 CNAME 落点与传播状态。</p>' +
        '</div></section>';

      html += '<div id="rq-result"></div><div id="rq-diagnose"></div>';

      root.innerHTML = html;
      renderQuery();
      renderDiagnose();

      root.onclick = async function (e) {
        var t = e.target;
        function attr(n) { return t.getAttribute && t.getAttribute(n); }
        try {
          // 解析查询
          var srvEl = t.closest ? t.closest('[data-srv]') : null;
          if (srvEl) {
            var srv = srvEl.getAttribute('data-srv');
            rq.servers.forEach(function (s) { if (s.server === srv) s.on = !s.on; });
            var box = document.getElementById('rq-servers');
            if (box) box.innerHTML = chips();
            return;
          }
          var actEl = t.closest ? t.closest('[data-act]') : null;
          var act = actEl ? actEl.getAttribute('data-act') : '';
          if (act === 'query') { await doQuery(); return; }
          if (act === 'diagnose') { await doDiagnose(); return; }

          // 服务商
          if (act === 'add') { providerModal(null); return; }
          if (attr('data-edit')) { var p1 = find(attr('data-edit')); if (p1) providerModal(p1); return; }
          if (attr('data-zones')) { var p2 = find(attr('data-zones')); if (p2) zonesModal(p2); return; }
          if (attr('data-test')) {
            var p3 = find(attr('data-test'));
            FG.toast('正在测试连接…');
            var r = await FG.api('api/dns/providers/' + attr('data-test') + '/verify', { method: 'POST' });
            FG.toast('✓ ' + ((r && r.message) || '连接正常'), 'ok');
            FG.refresh();
            return;
          }
          if (attr('data-del')) {
            var p4 = find(attr('data-del'));
            if (!await FG.confirmBox('删除「' + (p4 ? p4.name : '') + '」后，使用它的证书将无法自动续期。确认删除？', '删除 DNS 服务商')) return;
            await FG.api('api/dns/providers/' + attr('data-del'), { method: 'DELETE' });
            FG.toast('已删除', 'ok'); FG.refresh();
          }
        } catch (err) { FG.toast(err.message, 'err'); }
      };

      var nameEl = document.getElementById('rq-name');
      if (nameEl) {
        nameEl.addEventListener('keydown', function (ev) {
          if (ev.key === 'Enter') { ev.preventDefault(); doQuery().catch(function (err) { FG.toast(err.message, 'err'); }); }
        });
      }
      var typeEl = document.getElementById('rq-type');
      if (typeEl) typeEl.addEventListener('change', function () { rq.qtype = this.value; });
      var followEl = document.getElementById('rq-follow');
      if (followEl) followEl.addEventListener('change', function () { rq.follow = this.checked; });

      async function doQuery() {
        var name = (document.getElementById('rq-name') || {}).value || '';
        if (!name.trim()) { FG.toast('请输入要查询的域名', 'err'); return; }
        if (!selectedServers().length) { FG.toast('请至少选择一台 DNS 服务器', 'err'); return; }
        rq.name = name.trim();
        rq.qtype = (document.getElementById('rq-type') || {}).value || rq.qtype;
        var el = document.getElementById('rq-result');
        if (el) el.innerHTML = '<section class="panel"><div class="panel-body"><span class="spinner"></span> 正在查询 ' + FG.esc(name) + '…</div></section>';
        rq.lastQuery = await FG.api('api/dns/resolve/query', {
          method: 'POST',
          body: { name: rq.name, type: rq.qtype, servers: selectedServers(), follow: rq.follow }
        });
        renderQuery();
      }

      async function doDiagnose() {
        var name = (document.getElementById('rq-name') || {}).value || '';
        if (!name.trim()) { FG.toast('请输入要体检的域名', 'err'); return; }
        if (!selectedServers().length) { FG.toast('请至少选择一台 DNS 服务器', 'err'); return; }
        rq.name = name.trim();
        var el = document.getElementById('rq-diagnose');
        if (el) el.innerHTML = '<section class="panel"><div class="panel-body"><span class="spinner"></span> 正在体检 ' + FG.esc(name) + '…</div></section>';
        rq.lastDiagnose = await FG.api('api/dns/resolve/diagnose', {
          method: 'POST', body: { domain: rq.name, servers: selectedServers() }
        });
        renderDiagnose();
        el = document.getElementById('rq-diagnose');
        if (el && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  });
})();
