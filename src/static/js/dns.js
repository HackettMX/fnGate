(function () {
  'use strict';
  var FG = window.FG;
  var data = { providers: [] };
  var specs = [];

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
    title: 'DNS 服务商',
    sub: '管理 ACME 验证用的 DNS 凭据（DNSPod / 阿里云 / Cloudflare 等）',
    render: async function (root) {
      var res = await Promise.all([
        FG.api('api/dns/providers'),
        FG.api('api/dns/types').catch(function () { return { types: [] }; })
      ]);
      data = res[0] || data;
      specs = (res[1] && res[1].types) || specs;

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

      root.innerHTML = html;

      root.onclick = async function (e) {
        var t = e.target;
        function attr(n) { return t.getAttribute && t.getAttribute(n); }
        try {
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

    }
  });
})();
