(function () {
  'use strict';
  var FG = window.FG;

  FG.register('settings', {
    title: '设置',
    sub: '运行参数、配置备份与应用信息',
    render: async function (root) {
      var s = await FG.api('api/system/settings');
      var sys = await FG.api('api/system/status');
      root.innerHTML =
        '<section class="panel"><div class="panel-head"><div><h2>运行参数</h2><p>修改后立即生效，无需重启应用</p></div></div>' +
        '<div class="panel-body"><form id="settings-form"><div class="form-grid">' +
        '<div class="field"><label>路由器重启后自动补发映射</label>' +
        '<label class="checkbox"><input type="checkbox" id="s-reapply" ' + (s.auto_reapply ? 'checked' : '') + ' /> 自动把丢失的 UPnP 映射补回路由器</label>' +
        '<span class="hint">切换路由器或读取映射失败时会暂停补发，避免推送到陌生设备</span></div>' +
        '<div class="field"><label for="s-interval">自动补发核对间隔（秒）</label>' +
        '<input type="number" id="s-interval" min="15" max="3600" value="' + s.reapply_interval + '" /><span class="hint">15–3600，默认 60</span></div>' +
        '<div class="field"><label for="s-renew">证书续期提前天数</label>' +
        '<input type="number" id="s-renew" min="7" max="60" value="' + s.renew_days + '" /><span class="hint">7–60，默认 30 天</span></div>' +
        '<div class="field"><label for="s-hour">每日续期检查小时</label>' +
        '<input type="number" id="s-hour" min="0" max="23" value="' + s.renew_hour + '" /><span class="hint">0–23，默认凌晨 3 点</span></div>' +
        '<div class="field"><label for="s-health">后端健康检查间隔（秒）</label>' +
        '<input type="number" id="s-health" min="10" max="3600" value="' + s.health_interval + '" /><span class="hint">10–3600，默认 30</span></div>' +
        '<div class="field"><label for="s-level">日志级别</label><select id="s-level">' +
        ['DEBUG', 'INFO', 'WARN', 'ERROR'].map(function (l) {
          return '<option value="' + l + '"' + (s.log_level === l ? ' selected' : '') + '>' + l + '</option>';
        }).join('') + '</select></div>' +
        '<div class="field"><label>访问日志</label><label class="checkbox"><input type="checkbox" id="s-access" ' + (s.access_log ? 'checked' : '') + ' /> 记录代理请求与失败原因</label>' +
        '<span class="hint">日志只保存在本机应用数据目录</span></div>' +
        '<div class="field"><label for="s-dnsmode">DNS 传播校验方式</label><select id="s-dnsmode">' +
        [['auto', '自动（推荐）'], ['strict', '严格：要求所有权威 NS 生效'], ['recursive', '递归：解析器能查到即可']].map(function (o) {
          return '<option value="' + o[0] + '"' + ((s.dns_check_mode || 'auto') === o[0] ? ' selected' : '') + '>' + o[1] + '</option>';
        }).join('') + '</select><span class="hint">DNSPod 等不返回区域 NS 记录的 DNS，选「自动」即可</span></div>' +
        '<div class="field"><label for="s-dnswait">传播检查最长等待（秒）</label>' +
        '<input type="number" id="s-dnswait" min="60" max="1800" value="' + (s.dns_wait_sec || 180) + '" /><span class="hint">60–1800，默认 180</span></div>' +
        '<div class="field" style="grid-column:1/-1"><label for="s-dnsres">自定义 DNS 服务器（可选）</label>' +
        '<input type="text" id="s-dnsres" placeholder="223.5.5.5, 119.29.29.29" value="' + FG.esc((s.dns_resolvers || []).join(', ')) + '" />' +
        '<span class="hint">逗号分隔；留空则使用系统 DNS + 国内公共 DNS（223.5.5.5 / 119.29.29.29）</span></div>' +
        '</div><div style="margin-top:18px;display:flex;gap:9px"><button type="submit" class="btn btn-primary">保存设置</button>' +
        '<span class="muted" id="settings-tip" style="align-self:center;font-size:12px"></span></div></form></div></section>' +

        '<section class="panel"><div class="panel-head"><div><h2>配置备份</h2><p>导出内容不含证书私钥、ACME 账户密钥与 DNS 凭据</p></div></div>' +
        '<div class="panel-body"><div style="display:flex;gap:9px;flex-wrap:wrap">' +
        '<button type="button" class="btn" id="btn-export">导出配置</button>' +
        '<button type="button" class="btn" id="btn-import">从备份导入</button>' +
        '<input type="file" id="file-import" accept="application/json,.json" hidden />' +
        '</div><p class="hint" style="margin:12px 0 0;color:var(--text-3);font-size:12px">' +
        '导入会整体替换当前配置；若备份中包含 ACME 证书，需重新配置 DNS 凭据后才能自动续期。</p></div></section>' +

        '<section class="panel"><div class="panel-head"><div><h2>关于</h2></div></div><div class="panel-body">' +
        '<dl class="detail-list">' +
        '<dt>应用</dt><dd>路由网关 · fnGate v' + FG.esc(sys.version) + '</dd>' +
        '<dt>运行身份</dt><dd>' + FG.esc(sys.run_user) + '（uid ' + sys.euid + '）</dd>' +
        '<dt>低端口能力</dt><dd>' + (sys.can_bind_low ? '已具备 cap_net_bind_service，可绑定 80 / 443' : '不具备，需使用 1024 以上端口') + '</dd>' +
        '<dt>配置版本</dt><dd>v' + sys.schema_version + '</dd>' +
        '<dt>数据目录</dt><dd class="mono">$TRIM_PKGVAR</dd>' +
        '<dt>定时任务</dt><dd class="mono">' + FG.esc((sys.tasks || []).join(' · ') || '无') + '</dd>' +
        '</dl></div></section>';

      document.getElementById('settings-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        var payload = {
          auto_reapply: document.getElementById('s-reapply').checked,
          reapply_interval: parseInt(document.getElementById('s-interval').value, 10),
          renew_days: parseInt(document.getElementById('s-renew').value, 10),
          renew_hour: parseInt(document.getElementById('s-hour').value, 10),
          health_interval: parseInt(document.getElementById('s-health').value, 10),
          log_level: document.getElementById('s-level').value,
          access_log: document.getElementById('s-access').checked,
          default_cert_id: s.default_cert_id || '',
          dns_check_mode: document.getElementById('s-dnsmode').value,
          dns_wait_sec: parseInt(document.getElementById('s-dnswait').value, 10),
          dns_resolvers: document.getElementById('s-dnsres').value.split(/[,，\s]+/).filter(function (x) { return x; })
        };
        try {
          await FG.api('api/system/settings', { method: 'PUT', body: payload });
          FG.toast('设置已保存', 'ok');
        } catch (err) { FG.toast(err.message, 'err'); }
      });

      document.getElementById('btn-export').addEventListener('click', async function () {
        try {
          var res = await fetch('api/system/backup', { credentials: 'same-origin' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var blob = await res.blob();
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'fngate-state-' + new Date().toISOString().slice(0, 10) + '.json';
          a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
          FG.toast('已导出配置', 'ok');
        } catch (err) { FG.toast(err.message, 'err'); }
      });

      var file = document.getElementById('file-import');
      document.getElementById('btn-import').addEventListener('click', function () { file.click(); });
      file.addEventListener('change', async function () {
        if (!file.files || !file.files[0]) return;
        var text = await file.files[0].text();
        if (!await FG.confirmBox('导入会整体替换当前配置，确定继续？', '导入配置')) { file.value = ''; return; }
        try {
          var r = await FG.api('api/system/backup/import', { method: 'POST', body: text });
          FG.toast((r && r.note) || '配置已导入', 'ok');
          FG.refresh();
        } catch (err) { FG.toast(err.message, 'err'); }
        file.value = '';
      });
    }
  });

  FG.register('logs', {
    title: '日志',
    sub: '应用运行日志与事件记录',
    render: async function (root) {
      root.innerHTML = '<div class="tabs"><button type="button" class="tab active" data-tab="app">应用日志</button>' +
        '<button type="button" class="tab" data-tab="events">事件</button></div><div id="log-body"></div>';
      var body = document.getElementById('log-body');
      async function loadApp() {
        var r = await FG.api('api/system/logs?n=300');
        body.innerHTML = '<section class="panel"><div class="panel-head"><div><h2>最近 300 行</h2></div>' +
          '<div class="panel-actions"><button type="button" class="btn btn-sm" id="log-refresh">刷新</button></div></div>' +
          '<div class="panel-body"><div class="code-box">' + FG.esc((r.lines || []).join('\n') || '暂无日志') + '</div></div></section>';
        document.getElementById('log-refresh').addEventListener('click', loadApp);
      }
      async function loadEvents() {
        var r = await FG.api('api/system/events?after=0');
        var events = (r.events || []).slice().reverse();
        var h = '<section class="panel"><div class="panel-head"><div><h2>事件记录</h2></div>' +
          '<div class="panel-actions"><button type="button" class="btn btn-sm" id="log-refresh">刷新</button></div></div>';
        if (!events.length) { h += FG.empty('暂无事件', ''); } else {
          h += '<div class="table-wrap"><table><thead><tr><th>时间</th><th>模块</th><th>级别</th><th>内容</th></tr></thead><tbody>';
          events.forEach(function (e) {
            h += '<tr><td class="muted mono">' + FG.esc(e.time) + '</td><td>' + FG.esc(e.module) + '</td><td>' +
              FG.badge(e.level, e.level === 'error' ? 'tag-red' : (e.level === 'warn' ? 'tag-amber' : 'tag-green')) +
              '</td><td>' + FG.esc(e.message) + '</td></tr>';
          });
          h += '</tbody></table></div>';
        }
        body.innerHTML = h + '</section>';
        document.getElementById('log-refresh').addEventListener('click', loadEvents);
      }
      root.querySelectorAll('.tab').forEach(function (t) {
        t.addEventListener('click', function () {
          root.querySelectorAll('.tab').forEach(function (x) { x.classList.remove('active'); });
          t.classList.add('active');
          (t.getAttribute('data-tab') === 'app' ? loadApp : loadEvents)().catch(function (e) { FG.toast(e.message, 'err'); });
        });
      });
      await loadApp();
    }
  });
})();
