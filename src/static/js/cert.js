(function () {
  'use strict';
  var FG = window.FG;
  var data = { certificates: [] };
  // 主分类按来源做成 tab，状态只做筛选；两者与搜索叠加生效。
  var filters = { source: 'all', status: 'all', q: '' };

  var sourceLabel = {
    manual: '手动上传', fnos: '飞牛系统证书', acme: 'ACME 申请', selfsigned: '自签证书'
  };
  var sourceTabs = [
    ['all', '全部'], ['acme', 'ACME 申请'], ['manual', '手动上传'],
    ['selfsigned', '自签证书'], ['fnos', '飞牛系统证书']
  ];
  var statusOptions = [
    ['all', '全部状态'], ['valid', '有效'], ['expiring', '即将到期'],
    ['expired', '已过期'], ['missing', '文件缺失']
  ];

  function matchStatus(c, want) {
    if (want === 'all') return true;
    if (want === 'valid') return c.status === 'valid';
    return c.status === want;
  }

  function applyFilters(certs) {
    var q = filters.q.trim().toLowerCase();
    return certs.filter(function (c) {
      if (filters.source !== 'all' && c.source !== filters.source) return false;
      if (!matchStatus(c, filters.status)) return false;
      if (!q) return true;
      var hay = ((c.name || '') + ' ' + (c.primary_domain || '') + ' ' + (c.sans || []).join(' ')).toLowerCase();
      return hay.indexOf(q) >= 0;
    });
  }

  function tabsHTML(certs) {
    return sourceTabs.map(function (t) {
      var n = t[0] === 'all' ? certs.length : certs.filter(function (c) { return c.source === t[0]; }).length;
      return '<button type="button" class="tab' + (filters.source === t[0] ? ' active' : '') +
        '" data-source="' + t[0] + '">' + FG.esc(t[1]) + '<span class="cnt">' + n + '</span></button>';
    }).join('');
  }


  function card(icon, color, bg, label, value, sub, stat) {
    return '<div class="stat-card' + (stat ? ' stat-clickable' : '') + '"' +
      (stat ? ' data-stat="' + stat + '"' : '') + '>' +
      '<div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + label + '</span><span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }

  function daysTag(c) {
    if (c.status === 'missing') return FG.badge('文件缺失', 'tag-red');
    if (c.status === 'expired') return FG.badge('已过期 ' + Math.abs(c.days_left) + ' 天', 'tag-red');
    if (c.status === 'expiring') return FG.badge('剩 ' + c.days_left + ' 天', 'tag-amber');
    return FG.badge('剩 ' + c.days_left + ' 天', 'tag-green');
  }

  function statusTag(c) {
    var h = '';
    if (c.is_default) h += FG.badge('默认', 'tag-blue') + ' ';
    if (c.source === 'acme') h += FG.badge(c.auto_renew ? '自动续期' : '续期关闭', c.auto_renew ? 'tag-green' : 'tag-amber') + ' ';
    if (c.references > 0) h += FG.badge('引用 ' + c.references, 'tag-purple');
    return h || FG.badge('未使用', '');
  }

  function tableHTML(all) {
    var certs = applyFilters(all);
    if (!all.length) {
      return FG.empty('证书库还是空的', '可「上传证书」、生成自签证书，或点击「同步飞牛证书」导入系统已有证书');
    }
    if (!certs.length) {
      return FG.empty('当前筛选没有匹配的证书', '试试切换来源分类、状态，或清空搜索关键词');
    }
    var html = '<div class="table-wrap"><table><thead><tr><th>名称 / 主域名</th><th>SAN</th><th>来源</th><th>签发者</th>' +
      '<th>有效期</th><th>状态</th><th>操作</th></tr></thead><tbody>';
    certs.forEach(function (c) {
      var sans = (c.sans || []).slice(0, 3).map(function (d) { return FG.esc(d); }).join('<br>');
      if ((c.sans || []).length > 3) sans += '<br><span class="muted">+' + (c.sans.length - 3) + '</span>';
      html += '<tr><td><strong>' + FG.esc(c.name || c.primary_domain) + '</strong>' +
        '<br><span class="mono muted" style="font-size:12px">' + FG.esc(c.primary_domain) + '</span></td>' +
        '<td class="mono" style="font-size:12px">' + (sans || '<span class="muted">-</span>') + '</td>' +
        '<td>' + FG.badge(sourceLabel[c.source] || c.source, c.source === 'fnos' ? 'tag-purple' : (c.source === 'acme' ? 'tag-green' : 'tag-blue')) + '</td>' +
        '<td style="max-width:150px;overflow:hidden;text-overflow:ellipsis" title="' + FG.esc(c.issuer) + '">' + FG.esc(c.issuer) + '</td>' +
        '<td class="muted" style="font-size:12px;white-space:nowrap">' + FG.fmtDate(c.not_after) + '<br>' + daysTag(c) + '</td>' +
        '<td>' + statusTag(c) + '</td>' +
        '<td style="white-space:nowrap">' +
        '<span class="link" data-detail="' + FG.esc(c.id) + '">详情</span>' +
        '<span class="link" data-rename="' + FG.esc(c.id) + '">重命名</span>' +
        '<span class="link" data-default="' + FG.esc(c.id) + '">' + (c.is_default ? '取消默认' : '设为默认') + '</span>' +
        '<span class="link" data-download="' + FG.esc(c.id) + '">下载</span>' +
        '<span class="link" data-export="' + FG.esc(c.id) + '">导出</span>' +
        (c.source === 'acme' ? '<span class="link" data-renew="' + FG.esc(c.id) + '">' + (c.auto_renew ? '关闭续期' : '开启续期') + '</span>' +
          '<span class="link" data-renew-now="' + FG.esc(c.id) + '">立即续期</span>' : '') +
        '<span class="link danger" data-del="' + FG.esc(c.id) + '">删除</span>' +
        '</td></tr>';
    });
    return html + '</tbody></table></div>';
  }

  function uploadModal() {
    FG.modal({
      title: '上传证书', wide: true, submitText: '校验并保存',
      hint: '私钥仅写入应用私有目录（0600），不会出现在 API 响应或日志里',
      body: '<div class="form-grid">' +
        '<div class="field full"><label for="c-name">名称</label>' +
        '<input type="text" id="c-name" placeholder="留空则使用证书主域名" /></div>' +
        '<div class="field full"><label for="c-cert">证书链 PEM（含中间证书）</label>' +
        '<textarea id="c-cert" rows="9" placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"></textarea>' +
        '<span class="hint">按顺序粘贴站点证书与中间证书，可不含根证书</span></div>' +
        '<div class="field full"><label for="c-key">私钥 PEM</label>' +
        '<textarea id="c-key" rows="7" placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"></textarea>' +
        '<span class="hint">支持 PKCS#1、PKCS#8 与 EC 私钥；会校验是否与证书匹配</span></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onSubmit: async function (mask) {
        var certPEM = mask.querySelector('#c-cert').value.trim();
        var keyPEM = mask.querySelector('#c-key').value.trim();
        if (!certPEM || !keyPEM) { FG.fieldError(mask, '证书链与私钥都不能为空'); return false; }
        await FG.api('api/cert/upload', {
          method: 'POST',
          body: { name: mask.querySelector('#c-name').value.trim(), cert_pem: certPEM, key_pem: keyPEM }
        });
        FG.toast('证书已保存，可在 HTTPS 入口中选用', 'ok');
        FG.refresh();
      }
    });
  }

  function selfSignedModal() {
    FG.modal({
      title: '生成自签证书', submitText: '生成',
      hint: '自签证书不受浏览器信任，仅建议内网临时使用',
      body: '<div class="form-grid">' +
        '<div class="field full"><label for="ss-name">名称</label><input type="text" id="ss-name" placeholder="例如：内网测试" /></div>' +
        '<div class="field full"><label for="ss-domains">域名（逗号分隔，可写 *.example.com 或 IP）</label>' +
        '<input type="text" id="ss-domains" placeholder="nas.local, 192.168.1.10" /></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onSubmit: async function (mask) {
        var domains = mask.querySelector('#ss-domains').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        if (!domains.length) { FG.fieldError(mask, '请至少填写一个域名或 IP'); return false; }
        await FG.api('api/cert/selfsigned', {
          method: 'POST', body: { name: mask.querySelector('#ss-name').value.trim(), domains: domains }
        });
        FG.toast('自签证书已生成', 'ok');
        FG.refresh();
      }
    });
  }

  function detailModal(c, detail) {
    var sans = (c.sans || []).map(function (d) {
      return FG.badge(d, String(d).indexOf('*.') === 0 ? 'tag-purple' : '');
    }).join(' ') || '<span class="muted">无</span>';
    var refs = (detail.references || []).length
      ? '<ul style="margin:6px 0 0;padding-left:18px;line-height:1.9">' + detail.references.map(function (x) { return '<li>' + FG.esc(x) + '</li>'; }).join('') + '</ul>'
      : '<span class="muted">暂无引用</span>';
    FG.modal({
      title: '证书详情 · ' + (c.name || c.primary_domain), wide: true, readOnly: true,
      body: '<dl class="detail-list">' +
        '<dt>来源</dt><dd>' + FG.esc(sourceLabel[c.source] || c.source) + '</dd>' +
        '<dt>主域名</dt><dd class="mono">' + FG.esc(c.primary_domain) + '</dd>' +
        '<dt>密钥 / 链长</dt><dd>' + FG.esc(c.key_type || '未知') + ' · ' + (c.chain_length || 1) + ' 张证书</dd>' +
        '<dt>签发者</dt><dd>' + FG.esc(c.issuer) + '</dd>' +
        '<dt>有效期</dt><dd>' + FG.fmtDate(c.not_before) + ' ~ ' + FG.fmtDate(c.not_after) + ' ' + daysTag(c) + '</dd>' +
        '<dt>SHA-256 指纹</dt><dd class="mono" style="word-break:break-all">' + FG.esc(c.fingerprint) + '</dd>' +
        '<dt>SAN</dt><dd>' + sans + '</dd>' +
        '<dt>被引用</dt><dd>' + refs + '</dd>' +
        '</dl><h3 style="font-size:13px;margin:16px 0 8px">证书链（仅公钥，可安全复制）</h3>' +
        '<div class="code-box" style="max-height:240px;overflow:auto">' + FG.esc(detail.chain || '') + '</div>'
    });
  }

  function renameModal(c) {
    FG.modal({
      title: '重命名证书', submitText: '保存',
      body: '<div class="field"><label for="rn-name">名称</label>' +
        '<input type="text" id="rn-name" value="' + FG.esc(c.name) + '" /></div>' +
        '<div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onSubmit: async function (mask) {
        var name = mask.querySelector('#rn-name').value.trim();
        if (!name) { FG.fieldError(mask, '名称不能为空'); return false; }
        await FG.api('api/cert/' + c.id, { method: 'PUT', body: { name: name } });
        FG.toast('已重命名', 'ok'); FG.refresh();
      }
    });
  }

  FG.register('cert', {
    title: '证书管理',
    sub: '飞牛系统证书、手动上传与自签证书统一供给反向代理',
    render: async function (root) {
      data = await FG.api('api/cert/list');
      var certs = data.certificates || [];
      var fnosCount = certs.filter(function (c) { return c.source === 'fnos'; }).length;
      var failing = data.failing_orders || [];
      var expDays = data.expiring_days || 30;

      var html = '<section class="cards">' +
        card('▣', '#2f6fed', '#e9f0ff', '证书总数', certs.length, (data.default_cert_id ? '已设置默认证书' : '未设置默认证书'), 'all') +
        card('⏳', '#d97706', '#fff3e0', expDays + ' 天内到期', data.expiring || 0, '点击筛选即将到期', 'expiring') +
        card('!', (data.expired || 0) > 0 ? '#dc2626' : '#16a34a', (data.expired || 0) > 0 ? '#fdecec' : '#e8f7ed',
          '已过期', data.expired || 0, '请尽快替换或续期', 'expired') +
        card('◇', '#7c3aed', '#f1eafe', '飞牛系统证书', fnosCount, '只读导入，不回写系统证书库') +
        '</section>';

      if (data.missing) {
        html += '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body">' +
          '<strong>有 ' + data.missing + ' 张证书的文件缺失</strong><p>私钥或证书链文件不可读，HTTPS 入口会回退到自签证书。请重新上传或删除后重建。</p></div></div>';
      }
      if (failing.length) {
        html += '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body"><strong>证书申请失败</strong>' +
          failing.slice(0, 3).map(function (o) { return '<p>· ' + FG.esc(o.name || o.id) + '：' + FG.esc(o.error || '') + '</p>'; }).join('') + '</div></div>';
      }

      html += '<section class="panel"><div class="panel-head"><div><h2>证书列表 <span class="count-badge">' + certs.length +
        '</span></h2><p>在 HTTPS 入口或路由中按 ID 引用；续期后引用自动生效，无需重启</p></div>' +
        '<div class="panel-actions">' +
        '<button type="button" class="btn" data-act="sync">同步飞牛证书</button>' +
        '<button type="button" class="btn" data-act="selfsigned">+ 自签证书</button>' +
        '<button type="button" class="btn" data-act="acme">+ ACME 申请</button>' +
        '<button type="button" class="btn btn-primary" data-act="upload">+ 上传证书</button>' +
        '</div></div>' +
        '<div class="filter-bar">' +
        '<div class="tabs" id="cert-tabs">' + tabsHTML(certs) + '</div>' +
        '<div class="filter-right">' +
        '<select id="cert-status">' + statusOptions.map(function (o) {
          return '<option value="' + o[0] + '"' + (filters.status === o[0] ? ' selected' : '') + '>' + o[1] + '</option>';
        }).join('') + '</select>' +
        '<input type="text" id="cert-q" placeholder="搜索名称 / 域名" value="' + FG.esc(filters.q) + '" />' +
        '</div></div>' +
        '<div class="panel-body" style="padding:0" id="cert-table-wrap">' + tableHTML(certs) + '</div></section>';

      html += '<p class="hint" style="color:var(--text-3);font-size:12px">' +
        '飞牛系统证书为只读导入，不会修改飞牛证书库；同步由 root 侧 helper 生成私有快照，降权后的应用进程只读取快照。' +
        (data.fnos_synced_at ? '上次快照：' + FG.esc(data.fnos_synced_at) + '（' + (data.fnos_snapshot || 0) + ' 张）' : '尚未生成快照') +
        ' · 「下载」只给公钥证书链；「导出」会把证书链与私钥打包成 ZIP（二次确认后），用于导入飞牛系统证书。</p>';

      root.innerHTML = html;

      function repaint() {
        var wrap = document.getElementById('cert-table-wrap');
        if (wrap) wrap.innerHTML = tableHTML(certs);
        var tabs = document.getElementById('cert-tabs');
        if (tabs) tabs.innerHTML = tabsHTML(certs);
      }
      var sel = document.getElementById('cert-status');
      if (sel) sel.addEventListener('change', function () { filters.status = this.value; repaint(); });
      var q = document.getElementById('cert-q');
      if (q) q.addEventListener('input', function () { filters.q = this.value; repaint(); });

      root.onclick = async function (e) {
        var t = e.target;
        function attr(name) { return t.getAttribute && t.getAttribute(name); }
        function find(id) { for (var i = 0; i < certs.length; i++) if (certs[i].id === id) return certs[i]; return null; }
        try {
          var statEl = t.closest ? t.closest('[data-stat]') : null;
          if (statEl) {
            filters.status = statEl.getAttribute('data-stat');
            var selEl = document.getElementById('cert-status');
            if (selEl) selEl.value = filters.status;
            repaint();
            return;
          }
          var tab = t.closest ? t.closest('.tab') : null;
          if (tab && tab.getAttribute('data-source')) {
            filters.source = tab.getAttribute('data-source');
            repaint();
            return;
          }
          if (attr('data-act') === 'upload') { uploadModal(); return; }
          if (attr('data-act') === 'selfsigned') { selfSignedModal(); return; }
          if (attr('data-act') === 'acme') { FG.orderModal(); return; }
          if (attr('data-renew')) {
            var rc = find(attr('data-renew'));
            await FG.api('api/acme/certs/' + rc.id, { method: 'PUT', body: { auto_renew: !rc.auto_renew } });
            FG.toast(!rc.auto_renew ? '已开启自动续期' : '已关闭自动续期', 'ok'); FG.refresh();
            return;
          }
          if (attr('data-renew-now')) {
            await FG.api('api/acme/renew', { method: 'POST', body: { cert_id: attr('data-renew-now') } });
            FG.toast('续期任务已排队，可在「证书申请」查看进度', 'ok'); FG.refresh();
            return;
          }
          if (attr('data-act') === 'sync') {
            FG.toast('正在同步飞牛系统证书…');
            var s = await FG.api('api/cert/fnos/sync', { method: 'POST' });
            var msg = '同步完成：新增 ' + (s.imported || 0) + '、更新 ' + (s.updated || 0) + '、移除 ' + (s.removed || 0);
            if (s.note) msg += '。' + s.note;
            FG.toast(msg, 'ok');
            FG.refresh();
            return;
          }
          if (attr('data-detail')) {
            var d = await FG.api('api/cert/' + attr('data-detail'));
            detailModal(find(attr('data-detail')) || d.certificate, d);
            return;
          }
          if (attr('data-rename')) { renameModal(find(attr('data-rename'))); return; }
          if (attr('data-default')) {
            var c = find(attr('data-default'));
            var id = c.is_default ? '' : c.id;
            var r = await FG.api('api/cert/default', { method: 'POST', body: { id: id } });
            FG.toast(r.note || '已更新默认证书', 'ok'); FG.refresh();
            return;
          }
          if (attr('data-download')) {
            var res = await fetch('api/cert/' + attr('data-download') + '/download', { credentials: 'same-origin' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var blob = await res.blob();
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = (find(attr('data-download')).name || 'certificate') + '.pem';
            a.click();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
            return;
          }
          if (attr('data-export')) {
            var ec = find(attr('data-export'));
            var goOn = await FG.confirmBox(
              '导出包内含该证书的私钥（privkey.pem），用于导入飞牛系统证书。\n' +
              '私钥等同于域名身份，任何拿到它的人都能冒充该域名 —— 请勿转发，导入完成后删除本地副本。\n\n继续导出？',
              '导出证书包');
            if (!goOn) return;
            var resp = await fetch('api/cert/' + ec.id + '/export', {
              method: 'POST', credentials: 'same-origin',
              headers: { 'X-CSRF-Token': FG.csrf }
            });
            if (!resp.ok) {
              var msg = 'HTTP ' + resp.status;
              try { var j = await resp.json(); msg = j.error || msg; } catch (_) { }
              throw new Error(msg);
            }
            var zb = await resp.blob();
            var ea = document.createElement('a');
            ea.href = URL.createObjectURL(zb);
            ea.download = (ec.primary_domain || 'certificate') + '.zip';
            ea.click();
            setTimeout(function () { URL.revokeObjectURL(ea.href); }, 1000);
            FG.toast('已导出证书包（含私钥），用完请删除本地副本', 'ok');
            return;
          }
          if (attr('data-del')) {
            var target = find(attr('data-del'));
            if (!await FG.confirmBox('确认删除证书「' + (target.name || target.primary_domain) + '」？该操作会同时删除本机私钥文件。', '删除证书')) return;
            await FG.api('api/cert/' + target.id, { method: 'DELETE' });
            FG.toast('证书已删除', 'ok'); FG.refresh();
          }
        } catch (err) { FG.toast(err.message, 'err'); }
      };
    }
  });
})();
