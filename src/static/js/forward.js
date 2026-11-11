(function () {
  'use strict';
  var FG = window.FG;

  function leaseText(v) {
    if (!v) return '永久';
    if (v % 86400 === 0) return (v / 86400) + ' 天';
    if (v % 3600 === 0) return (v / 3600) + ' 小时';
    return v + ' 秒';
  }

  function card(icon, color, bg, label, value, sub) {
    return '<div class="stat-card"><div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + label + '</span><span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }

  function openAdd() {
    FG.modal({
      title: '添加端口映射',
      submitText: '确认添加',
      body: '<div class="form-grid">' +
        '<div class="field full"><label for="f-desc">描述（选填）</label><input type="text" id="f-desc" placeholder="例如：NAS 管理面板" maxlength="128" /></div>' +
        '<div class="field full"><label>协议</label><div class="seg" id="f-proto">' +
        '<button type="button" class="seg-item active" data-value="TCP">TCP</button>' +
        '<button type="button" class="seg-item" data-value="UDP">UDP</button></div></div>' +
        '<div class="field"><label for="f-ext">外部端口（必填）</label><input type="number" id="f-ext" min="1" max="65535" placeholder="1-65535" /></div>' +
        '<div class="field"><label for="f-int">内部端口（必填）</label><input type="number" id="f-int" min="1" max="65535" placeholder="1-65535" /></div>' +
        '<div class="field"><label for="f-ip">内部 IP（选填，默认本机）</label><input type="text" id="f-ip" placeholder="自动检测" /></div>' +
        '<div class="field"><label for="f-lease">租期</label><select id="f-lease">' +
        '<option value="0">永久</option><option value="3600">1 小时</option><option value="43200">12 小时</option>' +
        '<option value="86400">24 小时</option><option value="604800">7 天</option></select></div>' +
        '</div><div class="modal-error field-error" style="margin-top:12px" hidden></div>',
      onOpen: function (mask) {
        mask.querySelectorAll('#f-proto .seg-item').forEach(function (b) {
          b.addEventListener('click', function () {
            mask.querySelectorAll('#f-proto .seg-item').forEach(function (x) { x.classList.remove('active'); });
            b.classList.add('active');
          });
        });
      },
      onSubmit: async function (mask, close) {
        var ext = parseInt(mask.querySelector('#f-ext').value, 10);
        var int = parseInt(mask.querySelector('#f-int').value, 10);
        if (!ext || ext < 1 || ext > 65535 || !int || int < 1 || int > 65535) {
          FG.fieldError(mask, '请填写合法的外部端口与内部端口（1-65535）');
          return false;
        }
        var payload = {
          description: mask.querySelector('#f-desc').value.trim(),
          protocol: mask.querySelector('#f-proto .seg-item.active').getAttribute('data-value'),
          external_port: ext, internal_port: int,
          internal_client: mask.querySelector('#f-ip').value.trim(),
          lease_time: parseInt(mask.querySelector('#f-lease').value, 10)
        };
        await FG.api('api/forward/mappings', { method: 'POST', body: payload });
        FG.toast('映射已添加', 'ok');
        FG.refresh();
      }
    });
  }

  FG.register('forward', {
    title: '路由转发',
    sub: '通过 UPnP 管理路由器的 NAT 端口映射',
    render: async function (root) {
      var results = await Promise.all([
        FG.api('api/forward/status'),
        FG.api('api/forward/mappings')
      ]);
      var s = results[0] || {}, m = results[1] || {};
      var managed = m.managed || [], external = m.external || [];

      var html = '<section class="cards">' +
        card('◉', '#2f6fed', '#e9f0ff', '公网 IP', s.external_ip || '—', s.connected ? 'UPnP 网关已连接' : '未连接') +
        card('▤', '#7c3aed', '#f1eafe', '网关设备', s.gateway || '—', s.gateway_ip || '') +
        card('⇄', s.connected ? '#16a34a' : '#dc2626', s.connected ? '#e8f7ed' : '#fdecec',
          '连接状态', s.connected ? '已连接' : '未连接', s.error || '') +
        card('#', '#d97706', '#fff3e0', '端口映射', managed.length,
          '生效 ' + (s.active || 0) + ' · 未生效 ' + (s.missing || 0)) +
        '</section>';

      if (m.error) {
        html += '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body"><strong>无法读取网关</strong><p>' +
          FG.esc(m.error) + '</p></div></div>';
      }
      if (m.paused_reason) {
        html += '<div class="notice"><span class="notice-icon">!</span><div class="notice-body"><strong>自动补发已暂停</strong><p>' +
          FG.esc(m.paused_reason) + '</p></div></div>';
      }
      if (s.missing > 0 && !m.error) {
        html += '<div class="notice info"><span class="notice-icon">i</span><div class="notice-body"><strong>有 ' + s.missing +
          ' 条映射在路由器上未生效</strong><p>路由器重启或拨号重连会清空 NAT 表，可点「重新下发」立即补回。</p></div></div>';
      }

      html += '<section class="panel"><div class="panel-head"><div><h2>端口映射 <span class="count-badge">' + managed.length +
        '</span></h2><p>由本应用添加，可删除或重新启用</p></div><div class="panel-actions">' +
        '<button type="button" class="btn" data-act="discover">重新发现网关</button>' +
        '<button type="button" class="btn" data-act="reapply">重新下发</button>' +
        '<button type="button" class="btn btn-primary" data-act="add">+ 添加映射</button></div></div>';
      if (!managed.length) {
        html += FG.empty('还没有端口映射', '点击「添加映射」，把内网服务的端口发布到公网');
      } else {
        html += '<div class="table-wrap"><table><thead><tr><th>状态</th><th>协议</th><th>外部端口</th><th>内部地址</th>' +
          '<th>描述</th><th>租期</th><th>操作</th></tr></thead><tbody>';
        managed.forEach(function (x) {
          html += '<tr><td><span class="dot ' + (x.active ? 'dot-on' : 'dot-off') + '"></span> <span class="muted" title="' +
            FG.esc(x.error || '') + '">' + (x.active ? '已生效' : '未生效') + '</span></td>' +
            '<td>' + FG.badge(x.protocol, 'tag-blue') + '</td><td class="num">' + x.external_port + '</td>' +
            '<td class="mono">' + FG.esc(x.internal_client) + ':' + x.internal_port + '</td>' +
            '<td>' + FG.esc(x.description || '-') + '</td><td class="muted">' + leaseText(x.lease_time) + '</td>' +
            '<td><span class="link" data-enable="' + FG.esc(x.id) + '">重新启用</span>' +
            '<span class="link danger" data-del="' + FG.esc(x.id) + '">删除</span></td></tr>';
        });
        html += '</tbody></table></div>';
      }
      html += '</section>';

      html += '<section class="panel"><div class="panel-head"><div><h2>其他设备添加 <span class="count-badge">' + external.length +
        '</span></h2><p>路由器上已存在、非本应用托管的规则</p></div><span class="pill">只读展示 · 可清理</span></div>';
      if (!external.length) {
        html += FG.empty('没有其他设备添加的映射', '路由器 NAT 表中未发现其他规则');
      } else {
        html += '<div class="table-wrap"><table><thead><tr><th>协议</th><th>外部端口</th><th>内部地址</th><th>描述</th><th>状态</th><th>操作</th></tr></thead><tbody>';
        external.forEach(function (x) {
          html += '<tr><td>' + FG.badge(x.protocol, 'tag-blue') + '</td><td class="num">' + x.external_port + '</td>' +
            '<td class="mono">' + FG.esc(x.internal_client) + ':' + x.internal_port + '</td>' +
            '<td>' + FG.esc(x.description || '-') + '</td><td>' + (x.enabled ? '启用' : '停用') + '</td>' +
            '<td><span class="link danger" data-clean="' + x.external_port + '/' + x.protocol + '">清理</span></td></tr>';
        });
        html += '</tbody></table></div>';
      }
      html += '</section>';
      html += '<p class="hint" style="color:var(--text-3);font-size:12px">最近补发：' + FG.esc(m.last_reapply || '尚未执行') +
        ' · 需路由器开启 UPnP；卸载应用不会删除路由器上已生效的规则。</p>';
      root.innerHTML = html;

      root.onclick = async function (e) {
        var t = e.target;
        var act = t.getAttribute && t.getAttribute('data-act');
        try {
          if (act === 'add') { openAdd(); }
          else if (act === 'discover') { await FG.api('api/forward/discover', { method: 'POST' }); FG.toast('已重新发现网关', 'ok'); FG.refresh(); }
          else if (act === 'reapply') {
            var r = await FG.api('api/forward/reapply', { method: 'POST' });
            FG.toast('已补发 ' + (r.reapplied || 0) + ' 条映射', 'ok'); FG.refresh();
          } else if (t.getAttribute('data-del')) {
            if (!await FG.confirmBox('确认删除这条端口映射？', '删除映射')) return;
            var d = await FG.api('api/forward/mappings/' + t.getAttribute('data-del'), { method: 'DELETE' });
            FG.toast(d.warning || '映射已删除', d.warning ? '' : 'ok'); FG.refresh();
          } else if (t.getAttribute('data-enable')) {
            await FG.api('api/forward/mappings/' + t.getAttribute('data-enable') + '/enable', { method: 'POST' });
            FG.toast('映射已重新启用', 'ok'); FG.refresh();
          } else if (t.getAttribute('data-clean')) {
            var parts = t.getAttribute('data-clean').split('/');
            if (!await FG.confirmBox('这会删除路由器上的该条映射（端口 ' + parts[0] + '/' + parts[1] + '），确认继续？', '清理外部映射')) return;
            await FG.api('api/forward/external/' + parts[0] + '/' + parts[1], { method: 'DELETE' });
            FG.toast('已清理', 'ok'); FG.refresh();
          }
        } catch (err) { FG.toast(err.message, 'err'); }
      };
    }
  });
})();
