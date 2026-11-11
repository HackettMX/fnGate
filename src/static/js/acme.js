(function () {
  'use strict';
  var FG = window.FG;
  var data = { providers: [], accounts: [], orders: [], certificates: [] };
  var config = { cas: [], providers: [], key_types: [] };
  var loaded = false;

  var statusText = {
    pending: '排队中', waiting_dns: '待添加 TXT', validating: '验证中', issuing: '签发中',
    done: '已完成', failed: '失败', canceled: '已取消'
  };
  function statusTag(s) {
    var kind = { done: 'tag-green', failed: 'tag-red', waiting_dns: 'tag-amber', canceled: '' }[s] || 'tag-blue';
    return FG.badge(statusText[s] || s, kind);
  }
  function card(icon, color, bg, label, value, sub) {
    return '<div class="stat-card"><div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + label + '</span><span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }
  function providerName(id) {
    for (var i = 0; i < data.providers.length; i++) if (data.providers[i].id === id) return data.providers[i].name;
    return '已删除的服务商';
  }
  function caName(id) {
    for (var i = 0; i < config.cas.length; i++) if (config.cas[i].id === id) return config.cas[i].name;
    return id || 'Let\'s Encrypt';
  }

  // ---------- 申请任务弹窗（证书页也会调用） ----------
  FG.orderModal = async function (prefill) {
    if (!loaded) {
      var res = await Promise.all([FG.api('api/acme/config'), FG.api('api/acme/overview')]);
      config = res[0] || config;
      data = res[1] || data;
      loaded = true;
    }
    openOrderModal(prefill);
  };

  function openOrderModal(prefill) {
    prefill = prefill || {};
    var providerOpts = data.providers.map(function (p) {
      return '<option value="' + FG.esc(p.id) + '"' + (prefill.provider_id === p.id ? ' selected' : '') + '>' +
        FG.esc(p.name) + '</option>';
    }).join('');
    if (!data.providers.length) providerOpts = '<option value="">请先到「域名解析」页添加一个</option>';
    var accountOpts = '<option value="">自动选择 / 创建同 CA 的账户</option>' + data.accounts.map(function (a) {
      return '<option value="' + FG.esc(a.id) + '">' + FG.esc(caName(a.ca)) + (a.email ? ' · ' + FG.esc(a.email) : '') + '</option>';
    }).join('');
    var caOpts = config.cas.map(function (c) {
      return '<option value="' + FG.esc(c.id) + '"' + (c.id === 'letsencrypt' ? ' selected' : '') + '>' + FG.esc(c.name) + '</option>';
    }).join('');
    var keyOpts = config.key_types.map(function (k) {
      return '<option value="' + FG.esc(k.id) + '">' + FG.esc(k.name) + '</option>';
    }).join('');

    FG.modal({
      title: '使用 ACME 申请证书', wide: true, submitText: '创建申请任务',
      hint: 'DNS-01 支持泛域名；任务在后台执行，可随时查看进度',
      body: '<div class="form-grid">' +
        '<div class="field full"><label for="o-domains">域名（逗号或换行分隔，支持 *.example.com）</label>' +
        '<textarea id="o-domains" rows="3" placeholder="example.com, *.example.com">' + FG.esc(prefill.domains || '') + '</textarea>' +
        '<span class="hint">申请泛域名时建议同时写根域名与 *. 泛域名；两者会生成两条同名 TXT 记录</span></div>' +
        '<div class="field"><label for="o-provider">验证方式 / DNS 服务商</label><select id="o-provider">' + providerOpts + '</select></div>' +
        '<div class="field"><label for="o-account">ACME 账户</label><select id="o-account">' + accountOpts + '</select></div>' +
        '<div class="field"><label for="o-ca">证书颁发机构（CA）</label><select id="o-ca">' + caOpts + '</select></div>' +
        '<div class="field"><label for="o-email">邮箱（可选，用于到期提醒）</label><input type="text" id="o-email" placeholder="name@example.com" /></div>' +
        '<div class="field full" id="o-dir-wrap" hidden><label for="o-dir">自定义 ACME Directory URL</label>' +
        '<input type="text" id="o-dir" placeholder="https://acme.example.com/directory" /></div>' +
        '<div class="field" id="o-eab-kid-wrap" hidden><label for="o-eab-kid">EAB KID</label><input type="text" id="o-eab-kid" /></div>' +
        '<div class="field" id="o-eab-hmac-wrap" hidden><label for="o-eab-hmac">EAB HMAC</label><input type="text" id="o-eab-hmac" /></div>' +
        '<div class="field"><label for="o-key">证书密钥类型</label><select id="o-key">' + keyOpts + '</select></div>' +
        '<div class="field"><label class="checkbox"><input type="checkbox" id="o-renew" checked /> 到期前自动续期</label>' +
        '<span class="hint">默认提前 30 天，在「设置」页可调整</span></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onOpen: function (mask) {
        function toggle() {
          var ca = mask.querySelector('#o-ca').value;
          var custom = ca === 'custom';
          var eab = ca === 'zerossl' || custom;
          mask.querySelector('#o-dir-wrap').hidden = !custom;
          mask.querySelector('#o-eab-kid-wrap').hidden = !eab;
          mask.querySelector('#o-eab-hmac-wrap').hidden = !eab;
        }
        mask.querySelector('#o-ca').addEventListener('change', toggle);
        toggle();
      },
      onSubmit: async function (mask) {
        var domains = mask.querySelector('#o-domains').value.split(/[,，\n\r]+/).map(function (s) { return s.trim(); }).filter(Boolean);
        if (!domains.length) { FG.fieldError(mask, '请至少填写一个域名'); return false; }
        var payload = {
          domains: domains,
          provider_id: mask.querySelector('#o-provider').value,
          account_id: mask.querySelector('#o-account').value,
          ca: mask.querySelector('#o-ca').value,
          directory_url: mask.querySelector('#o-dir').value.trim(),
          email: mask.querySelector('#o-email').value.trim(),
          eab_kid: mask.querySelector('#o-eab-kid').value.trim(),
          eab_hmac: mask.querySelector('#o-eab-hmac').value.trim(),
          key_type: mask.querySelector('#o-key').value || 'ec256',
          auto_renew: mask.querySelector('#o-renew').checked
        };
        if (!payload.provider_id) { FG.fieldError(mask, '请先到「域名解析」页添加一个服务商（可选「手动添加 TXT 记录」）'); return false; }
        await FG.api('api/acme/orders', { method: 'POST', body: payload });
        FG.toast('申请任务已创建，可在「证书申请」查看进度', 'ok');
        FG.refresh();
      }
    });
  };

  // ---------- 账户弹窗 ----------

  function accountModal() {
    FG.modal({
      title: '添加 ACME 账户', wide: true, submitText: '保存账户',
      hint: '账户密钥由应用自动生成并保存在 secrets/；不填写账户也可直接申请',
      body: '<div class="form-grid">' +
        '<div class="field"><label for="a-ca">CA</label><select id="a-ca">' +
        config.cas.map(function (c) { return '<option value="' + c.id + '">' + FG.esc(c.name) + '</option>'; }).join('') + '</select></div>' +
        '<div class="field"><label for="a-email">邮箱</label><input type="text" id="a-email" placeholder="name@example.com" /></div>' +
        '<div class="field full"><label for="a-dir">自定义 Directory URL（仅自定义 CA 需要）</label>' +
        '<input type="text" id="a-dir" placeholder="https://acme.example.com/directory" /></div>' +
        '<div class="field"><label for="a-kid">EAB KID（可选）</label><input type="text" id="a-kid" /></div>' +
        '<div class="field"><label for="a-hmac">EAB HMAC（可选）</label><input type="text" id="a-hmac" /></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onSubmit: async function (mask) {
        await FG.api('api/acme/accounts', { method: 'POST', body: {
          ca: mask.querySelector('#a-ca').value,
          directory_url: mask.querySelector('#a-dir').value.trim(),
          email: mask.querySelector('#a-email').value.trim(),
          eab_kid: mask.querySelector('#a-kid').value.trim(),
          eab_hmac: mask.querySelector('#a-hmac').value.trim()
        } });
        FG.toast('ACME 账户已创建', 'ok'); FG.refresh();
      }
    });
  }

  function orderDetailModal(o) {
    var txt = (o.manual_txt || []).length
      ? '<div class="table-wrap"><table><thead><tr><th>TXT 记录名</th><th>记录值</th></tr></thead><tbody>' +
        o.manual_txt.map(function (r) {
          return '<tr><td class="mono">' + FG.esc(r.domain) + '</td><td class="mono" style="word-break:break-all">' + FG.esc(r.value) + '</td></tr>';
        }).join('') + '</tbody></table></div>'
      : '';
    var h = '<dl class="detail-list">' +
      '<dt>状态</dt><dd>' + statusTag(o.status) + '</dd>' +
      '<dt>域名</dt><dd class="mono">' + FG.esc((o.domains || []).join(', ')) + '</dd>' +
      '<dt>验证方式</dt><dd>DNS-01 · ' + FG.esc(providerName(o.provider_id)) + '</dd>' +
      '<dt>CA / 密钥</dt><dd>' + FG.esc(caName(o.ca)) + ' · ' + FG.esc(o.key_type || 'ec256') + '</dd>' +
      '<dt>创建时间</dt><dd>' + FG.fmtDate(o.created_at) + '</dd>' +
      (o.error ? '<dt>错误</dt><dd style="color:#dc2626">' + FG.esc(o.error) + '</dd>' : '') +
      '</dl>';
    if (txt) h += '<h3 style="font-size:13px;margin:16px 0 8px">需要添加的 TXT 记录</h3>' + txt +
      '<p class="hint" style="color:var(--text-3);font-size:12px">同名多条记录请全部添加为独立 TXT 值；添加后点「我已添加，继续验证」，系统也会自动探测 DNS 生效。</p>';
    h += '<h3 style="font-size:13px;margin:16px 0 8px">任务日志</h3><div class="code-box" style="max-height:220px;overflow:auto">' +
      FG.esc((o.logs || []).join('\n') || '暂无日志') + '</div>';
    FG.modal({
      title: '证书申请详情', wide: true, readOnly: !o.can_confirm,
      submitText: o.can_confirm ? '我已添加，继续验证' : '关闭',
      body: h,
      onSubmit: o.can_confirm ? async function () {
        await FG.api('api/acme/orders/' + o.id + '/continue', { method: 'POST' });
        FG.toast('已确认，正在继续校验', 'ok'); FG.refresh();
      } : null
    });
  }

  async function render(root) {
    var res = await Promise.all([
      FG.api('api/acme/config'),
      FG.api('api/acme/overview')
    ]);
    config = res[0] || config;
    data = res[1] || data;
    loaded = true;
    var orders = data.orders || [], providers = data.providers || [], accounts = data.accounts || [];
    var acmeCerts = (data.certificates || []).filter(function (c) { return c.source === 'acme'; });
    var active = orders.filter(function (o) { return ['pending', 'waiting_dns', 'validating', 'issuing'].indexOf(o.status) >= 0; }).length;
    var failed = orders.filter(function (o) { return o.status === 'failed'; }).length;
    var waiting = orders.filter(function (o) { return o.status === 'waiting_dns'; });

    var html = '<section class="cards">' +
      card('⟳', '#2f6fed', '#e9f0ff', '进行中任务', active, '后台执行，可关闭页面') +
      card('!', failed ? '#dc2626' : '#16a34a', failed ? '#fdecec' : '#e8f7ed', '失败任务', failed, '支持一键重试与指数退避') +
      card('◇', '#7c3aed', '#f1eafe', '可用服务商', providers.length, '已拆分到独立页面管理') +
      card('▣', '#16a34a', '#e8f7ed', '自动续期证书', data.auto_renew_certs || 0, '到期前自动重新签发') +
      '</section>';

    if (waiting.length) {
      html += '<div class="notice"><span class="notice-icon">!</span><div class="notice-body"><strong>' + waiting.length +
        ' 个任务正在等待手动添加 TXT 记录</strong><p>打开任务详情查看记录名与值，添加完成后点「我已添加，继续验证」；系统也会自动轮询 DNS 生效。</p></div></div>';
    }

    // 申请任务
    html += '<section class="panel"><div class="panel-head"><div><h2>申请任务 <span class="count-badge">' + orders.length +
      '</span></h2><p>创建订单 → DNS-01 验证 → 签发 → 原子落盘 → 反代引用自动生效</p></div>' +
      '<div class="panel-actions"><button type="button" class="btn" data-act="provider">域名解析</button>' +
      '<button type="button" class="btn btn-primary" data-act="order">+ 申请证书</button></div></div><div class="panel-body" style="padding:0">';
    if (!orders.length) {
      html += FG.empty('还没有申请任务', '先到「域名解析」页配置 DNS 服务商，再点「申请证书」；泛域名请填写 *.example.com');
    } else {
      html += '<div class="table-wrap"><table><thead><tr><th>状态</th><th>域名</th><th>CA / 验证</th><th>时间</th><th>说明</th><th>操作</th></tr></thead><tbody>';
      orders.forEach(function (o) {
        html += '<tr><td>' + statusTag(o.status) + '</td>' +
          '<td class="mono" style="font-size:12px">' + (o.domains || []).map(function (d) { return FG.esc(d); }).join('<br>') + '</td>' +
          '<td>' + FG.esc(caName(o.ca)) + '<br><span class="muted" style="font-size:12px">' + FG.esc(providerName(o.provider_id)) + '</span></td>' +
          '<td class="muted" style="font-size:12px">' + FG.fmtDate(o.created_at) + '</td>' +
          '<td style="font-size:12px">' + (o.error ? '<span style="color:#dc2626">' + FG.esc(o.error) + '</span>' :
            (o.status === 'waiting_dns' ? '需添加 ' + (o.manual_txt || []).length + ' 条 TXT 记录' :
              (o.status === 'done' ? '证书已入库，cert_id 可在反代引用' : (o.logs || []).slice(-1)[0] || ''))) + '</td>' +
          '<td style="white-space:nowrap"><span class="link" data-order-detail="' + o.id + '">详情</span>' +
          (o.can_confirm ? '<span class="link" data-order-continue="' + o.id + '">继续验证</span>' : '') +
          (o.running ? '<span class="link" data-order-cancel="' + o.id + '">取消</span>' : '') +
          ((o.status === 'failed' || o.status === 'canceled') ? '<span class="link" data-order-retry="' + o.id + '">重试</span>' : '') +
          (!o.running ? '<span class="link danger" data-order-del="' + o.id + '">删除</span>' : '') +
          '</td></tr>';
      });
      html += '</tbody></table></div>';
    }
    html += '</div></section>';

    // ACME 账户
    html += '<section class="panel"><div class="panel-head"><div><h2>ACME 账户</h2>' +
      '<p>支持 Let&#39;s Encrypt / Staging / ZeroSSL / 自定义 Directory，含 EAB</p></div><div class="panel-actions">' +
      '<button type="button" class="btn" data-act="account">+ 添加账户</button></div></div><div class="panel-body" style="padding:0">';
    if (!accounts.length) {
      html += FG.empty('暂无账户', '直接创建申请任务时会自动生成一个账户；也可在此显式管理');
    } else {
      html += '<div class="table-wrap"><table><thead><tr><th>CA</th><th>邮箱</th><th>Directory</th><th>EAB</th><th>操作</th></tr></thead><tbody>';
      accounts.forEach(function (x) {
        html += '<tr><td>' + FG.esc(caName(x.ca)) + '</td><td>' + FG.esc(x.email || '-') + '</td>' +
          '<td class="mono" style="font-size:11.5px;max-width:260px;overflow:hidden;text-overflow:ellipsis">' + FG.esc(x.directory_url) + '</td>' +
          '<td>' + (x.has_eab ? FG.badge('已配置', 'tag-green') : '-') + '</td>' +
          '<td><span class="link danger" data-account-del="' + x.id + '">删除</span></td></tr>';
      });
      html += '</tbody></table></div>';
    }
    html += '</div></section>';

    // 自动续期证书
    html += '<section class="panel"><div class="panel-head"><div><h2>自动续期</h2>' +
      '<p>到期前按「设置」中的天数检查，续期保持 cert_id 不变，引用方零重启生效</p></div></div><div class="panel-body" style="padding:0">';
    if (!acmeCerts.length) {
      html += FG.empty('还没有 ACME 证书', '签发成功后会出现在这里');
    } else {
      html += '<div class="table-wrap"><table><thead><tr><th>证书</th><th>到期</th><th>自动续期</th><th>状态</th><th>操作</th></tr></thead><tbody>';
      acmeCerts.forEach(function (c) {
        html += '<tr><td>' + FG.esc(c.name) + '<br><span class="mono muted" style="font-size:12px">' + FG.esc(c.primary_domain) + '</span></td>' +
          '<td>' + FG.fmtDate(c.not_after) + '<br>' + (c.status === 'expired' ? FG.badge('已过期', 'tag-red') : FG.badge('剩 ' + c.days_left + ' 天', c.days_left <= 30 ? 'tag-amber' : 'tag-green')) + '</td>' +
          '<td>' + (c.auto_renew ? FG.badge('开启', 'tag-green') : FG.badge('关闭', '')) + '</td>' +
          '<td style="font-size:12px">' + (c.last_error ? '<span style="color:#dc2626">' + FG.esc(c.last_error) + '</span>' :
            (c.next_renew_at ? '下次检查 ' + FG.fmtDate(c.next_renew_at) : '正常')) + '</td>' +
          '<td style="white-space:nowrap"><span class="link" data-toggle-renew="' + c.id + '">' + (c.auto_renew ? '关闭续期' : '开启续期') + '</span>' +
          '<span class="link" data-renew-now="' + c.id + '">立即续期</span></td></tr>';
      });
      html += '</tbody></table></div>';
    }
    html += '</div></section>';
    html += '<p class="hint" style="color:var(--text-3);font-size:12px">' + FG.esc(config.note || '') +
      ' 失败按 1 小时 / 6 小时 / 24 小时退避重试；续期期间旧证书继续服务，新证书校验失败自动回滚。</p>';

    root.innerHTML = html;
    root.onclick = async function (e) {
      var t = e.target;
      function attr(n) { return t.getAttribute && t.getAttribute(n); }
      function findOrder(id) { for (var i = 0; i < orders.length; i++) if (orders[i].id === id) return orders[i]; return null; }
      try {
        if (attr('data-act') === 'order') { FG.orderModal(); return; }
        if (attr('data-act') === 'provider') { FG.show('dns'); return; }
        if (attr('data-act') === 'account') { accountModal(); return; }
        if (attr('data-order-detail')) { orderDetailModal(findOrder(attr('data-order-detail'))); return; }
        if (attr('data-order-continue')) {
          await FG.api('api/acme/orders/' + attr('data-order-continue') + '/continue', { method: 'POST' });
          FG.toast('已确认，正在继续校验', 'ok'); FG.refresh(); return;
        }
        if (attr('data-order-cancel')) {
          await FG.api('api/acme/orders/' + attr('data-order-cancel') + '/cancel', { method: 'POST' });
          FG.toast('任务已取消', 'ok'); FG.refresh(); return;
        }
        if (attr('data-order-retry')) {
          await FG.api('api/acme/orders/' + attr('data-order-retry') + '/retry', { method: 'POST' });
          FG.toast('任务已重新排队', 'ok'); FG.refresh(); return;
        }
        if (attr('data-order-del')) {
          if (!await FG.confirmBox('确认删除该申请任务记录？', '删除任务')) return;
          await FG.api('api/acme/orders/' + attr('data-order-del'), { method: 'DELETE' });
          FG.toast('任务已删除', 'ok'); FG.refresh(); return;
        }
        if (attr('data-account-del')) {
          if (!await FG.confirmBox('删除账户会一并删除其密钥与注册信息，确认继续？', '删除 ACME 账户')) return;
          await FG.api('api/acme/accounts/' + attr('data-account-del'), { method: 'DELETE' });
          FG.toast('账户已删除', 'ok'); FG.refresh(); return;
        }
        if (attr('data-toggle-renew')) {
          var c = null;
          for (var j = 0; j < acmeCerts.length; j++) if (acmeCerts[j].id === attr('data-toggle-renew')) c = acmeCerts[j];
          await FG.api('api/acme/certs/' + c.id, { method: 'PUT', body: { auto_renew: !c.auto_renew } });
          FG.toast(!c.auto_renew ? '已开启自动续期' : '已关闭自动续期', 'ok'); FG.refresh(); return;
        }
        if (attr('data-renew-now')) {
          await FG.api('api/acme/renew', { method: 'POST', body: { cert_id: attr('data-renew-now') } });
          FG.toast('续期任务已排队', 'ok'); FG.refresh(); return;
        }
      } catch (err) { FG.toast(err.message, 'err'); }
    };
  }

  FG.register('acme', {
    title: '证书申请',
    sub: 'DNS-01 泛域名申请与自动续期；服务商凭据在「域名解析」页管理',
    render: render,
    poll: render
  });
})();
