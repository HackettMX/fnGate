(function () {
  'use strict';
  var FG = window.FG;

  function safe(promise, fallback) {
    return promise.catch(function () { return fallback; });
  }

  function card(icon, color, bg, label, value, sub) {
    return '<div class="stat-card">' +
      '<div class="stat-icon" style="--c:' + color + ';--bg:' + bg + '">' + icon + '</div>' +
      '<div class="stat-meta"><span class="stat-label">' + FG.esc(label) + '</span>' +
      '<span class="stat-value">' + FG.esc(value) + '</span>' +
      '<span class="stat-sub">' + FG.esc(sub || '') + '</span></div></div>';
  }

  FG.register('overview', {
    title: '概览',
    sub: '网关、转发与证书的运行状态',
    render: async function (root) {
      var results = await Promise.all([
        FG.api('api/system/status'),
        safe(FG.api('api/forward/status'), {}),
        safe(FG.api('api/proxy/status'), {}),
        safe(FG.api('api/cert/list'), {}),
        safe(FG.api('api/system/events?after=0'), { events: [] })
      ]);
      var sys = results[0] || {}, fwd = results[1] || {}, px = results[2] || {},
        cert = results[3] || {}, ev = results[4] || {};

      var certs = cert.certificates || [];
      var expiring = certs.filter(function (c) {
        var d = FG.daysUntil(c.not_after);
        return d != null && d <= 30;
      }).length;
      var listeners = px.listeners || [];
      var activeListeners = listeners.filter(function (l) { return l.active; }).length;
      var failed = (px.failed || 0) + (fwd.missing || 0);
      var counts = sys.counts || {};

      var html = '<section class="cards">' +
        card('◉', '#2f6fed', '#e9f0ff', '公网 IP', fwd.external_ip || '—', fwd.connected ? 'UPnP 网关已连接' : '未连接网关') +
        card('⇄', '#16a34a', '#e8f7ed', '端口映射', fwd.managed != null ? fwd.managed : (counts.forwards || 0),
          '生效 ' + (fwd.active != null ? fwd.active : 0) + ' · 未生效 ' + (fwd.missing || 0)) +
        card('⇥', '#7c3aed', '#f1eafe', '反代监听', activeListeners + ' / ' + listeners.length,
          '路由 ' + (counts.routes || 0) + ' 条') +
        card('▣', '#d97706', '#fff3e0', '证书', certs.length, expiring ? expiring + ' 张将在 30 天内到期' : '暂无临期证书') +
        card('!', failed > 0 ? '#dc2626' : '#16a34a', failed > 0 ? '#fdecec' : '#e8f7ed',
          '未生效项', failed, failed ? '请查看对应模块' : '全部正常') +
        '</section>';

      if (sys.can_bind_low === false) {
        html += '<div class="notice"><span class="notice-icon">!</span><div class="notice-body">' +
          '<strong>当前无法绑定 1024 以下端口</strong><p>进程以 ' + FG.esc(sys.run_user || '未知用户') +
          ' 运行且缺少 cap_net_bind_service，80 / 443 这类规则会保存但无法生效。请重启应用，或改用高位端口并在路由器做映射。</p></div></div>';
      }

      var problems = [];
      listeners.forEach(function (l) {
        if (!l.active && l.error) problems.push('端口 ' + l.port + '：' + l.error);
      });
      certs.forEach(function (c) {
        var d = FG.daysUntil(c.not_after);
        if (d != null && d <= 30) problems.push('证书 ' + (c.name || c.primary_domain) + '：' + (d < 0 ? '已过期' : d + ' 天后到期'));
      });
      (cert.failing_orders || []).forEach(function (o) { problems.push('证书申请失败：' + (o.name || o.id)); });
      if (problems.length) {
        html += '<div class="notice danger"><span class="notice-icon">!</span><div class="notice-body"><strong>需要处理的 ' + problems.length + ' 项</strong>' +
          problems.slice(0, 6).map(function (p) { return '<p>· ' + FG.esc(p) + '</p>'; }).join('') + '</div></div>';
      }

      html += '<section class="panel"><div class="panel-head"><div><h2>监听端口</h2><p>反向代理当前生效的入口</p></div></div>';
      if (!listeners.length) {
        html += FG.empty('还没有监听入口', '到「反向代理」新增一个入口后，这里会显示它的状态');
      } else {
        html += '<div class="table-wrap"><table><thead><tr><th>状态</th><th>端口</th><th>协议</th><th>路由数</th><th>说明</th></tr></thead><tbody>';
        listeners.forEach(function (l) {
          html += '<tr><td><span class="dot ' + (l.active ? 'dot-on' : 'dot-off') + '"></span></td>' +
            '<td class="num">' + l.port + '</td><td>' + FG.badge(String(l.protocol || '').toUpperCase(), l.protocol === 'https' ? 'tag-purple' : 'tag-blue') + '</td>' +
            '<td class="num">' + (l.routes || 0) + '</td><td class="muted">' + FG.esc(l.error || '正常') + '</td></tr>';
        });
        html += '</tbody></table></div>';
      }
      html += '</section>';

      var events = (ev.events || []).slice(-8).reverse();
      html += '<section class="panel"><div class="panel-head"><div><h2>最近事件</h2><p>配置变更、证书续期与异常</p></div></div>';
      if (!events.length) {
        html += FG.empty('暂无事件', '应用启动后的操作会记录在这里');
      } else {
        html += '<div class="table-wrap"><table><thead><tr><th>时间</th><th>模块</th><th>级别</th><th>内容</th></tr></thead><tbody>';
        events.forEach(function (e) {
          html += '<tr><td class="muted mono">' + FG.esc(e.time) + '</td><td>' + FG.esc(e.module) + '</td>' +
            '<td>' + FG.badge(e.level, e.level === 'error' ? 'tag-red' : (e.level === 'warn' ? 'tag-amber' : 'tag-green')) + '</td>' +
            '<td>' + FG.esc(e.message) + '</td></tr>';
        });
        html += '</tbody></table></div>';
      }
      html += '</section>';

      root.innerHTML = html;
    }
  });
})();
