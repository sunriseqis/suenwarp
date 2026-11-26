<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { AuthError, apiFetch, copyText, getStoredToken, setStoredToken } from './api'

const token = ref(getStoredToken())
const tokenInput = ref(token.value)
const authed = ref(false)
const loginErr = ref('')
const activeTab = ref('overview')

const state = ref(null)
const history = ref([])
const schema = ref([])
const configData = ref({})
const envOverrides = ref({})
const formValues = reactive({})

const wb = ref(null)
const wbPass = ref('')
const sourceList = ref([])
const newSourceKind = ref('vless_ip')
const newSourceUrl = ref('')
const addingSource = ref(false)
const refreshingUrl = ref('')

const toast = ref({ show: false, text: '', type: 'ok' })
let pollTimer = null
let toastTimer = null

function notify(text, type = 'ok') {
  toast.value = { show: true, text, type }
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toast.value.show = false
  }, 2600)
}

function getByPath(obj, path) {
  return path.split('.').reduce((acc, k) => (acc && acc[k] !== undefined ? acc[k] : undefined), obj)
}

function initForm(cfg, groups) {
  for (const g of groups) {
    for (const f of g.fields) {
      const val = getByPath(cfg, f.key)
      if (f.type === 'list') {
        formValues[f.key] = Array.isArray(val) ? val.join('\n') : (val || '')
      } else if (f.type === 'bool') {
        formValues[f.key] = Boolean(val)
      } else {
        formValues[f.key] = val ?? ''
      }
    }
  }
}

const subUrls = computed(() => {
  const origin = window.location.origin
  const q = token.value ? `&token=${encodeURIComponent(token.value)}` : ''
  return {
    clash: `${origin}/sub?target=clash${q}`,
    v2ray: `${origin}/sub?target=v2ray${q}`,
  }
})

const vlessNodes = computed(() => (state.value?.nodes || []).filter(n => (n.class || 'vless') === 'vless'))
const fallbackNodes = computed(() => (state.value?.nodes || []).filter(n => n.class === 'fallback'))

const progressText = computed(() => {
  const p = state.value?.progress
  if (!state.value?.running) return '定时守护中'
  if (!p?.stage) return '扫描中…'
  return p.total ? `${p.stage} (${p.done}/${p.total})` : p.stage
})

function aiStatus(n) {
  if (typeof n.ai_ok === 'boolean') {
    return { ok: n.ai_ok, label: n.ai_ok ? '✓ 可用' : '✗ 受限', detail: n.ai_detail || '' }
  }
  const map = n.domain_ok || {}
  const keys = Object.keys(map)
  if (!keys.length) return { ok: null, label: '未测', detail: '未进入验证短名单' }
  const allOk = keys.every(k => map[k])
  return {
    ok: allOk,
    label: allOk ? '✓ 可用' : '✗ 受限',
    detail: keys.map(k => `${k}: ${map[k] ? '✓' : '✗'}`).join(' · '),
  }
}

function sparkPath(points, w = 600, h = 90) {
  if (!points.length) return ''
  const max = Math.max(...points, 1)
  const min = Math.min(...points, 0)
  const span = max - min || 1
  const step = points.length > 1 ? w / (points.length - 1) : w
  return points
    .map((v, i) => {
      const x = (i * step).toFixed(1)
      const y = (h - ((v - min) / span) * (h - 8) - 4).toFixed(1)
      return `${i ? 'L' : 'M'}${x},${y}`
    })
    .join(' ')
}

const latencySpark = computed(() => sparkPath(history.value.slice(-30).map(x => Number(x.best_latency_ms) || 0)))
const passedSpark = computed(() => sparkPath(history.value.slice(-30).map(x => Number(x.passed) || 0)))

async function loadState() {
  const s = await apiFetch('/api/state', {}, token.value)
  state.value = s
  sourceList.value = Array.isArray(s.sources) ? s.sources : []
  authed.value = true
  if (s.running) startPolling()
  else stopPolling()
}

async function loadAll() {
  await loadState()
  const [hist, cfgRes, wbRes] = await Promise.all([
    apiFetch('/api/history', {}, token.value),
    apiFetch('/api/config', {}, token.value),
    apiFetch('/api/writeback', {}, token.value),
  ])
  history.value = Array.isArray(hist) ? hist : []
  if (cfgRes?.ok) {
    schema.value = cfgRes.schema || []
    configData.value = cfgRes.config || {}
    envOverrides.value = cfgRes.env || {}
    initForm(configData.value, schema.value)
  }
  if (wbRes?.ok) wb.value = wbRes.writeback
}

function startPolling() {
  if (pollTimer) return
  pollTimer = setInterval(async () => {
    try {
      const wasRunning = state.value?.running
      await loadState()
      if (wasRunning && !state.value?.running) {
        const hist = await apiFetch('/api/history', {}, token.value)
        history.value = Array.isArray(hist) ? hist : []
        notify('扫描已完成')
      }
    } catch {
      stopPolling()
    }
  }, 2500)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function connect() {
  loginErr.value = ''
  token.value = tokenInput.value.trim()
  setStoredToken(token.value)
  try {
    await loadAll()
  } catch (e) {
    authed.value = false
    loginErr.value = e instanceof AuthError ? e.message : (e.message || '连接失败')
  }
}

function logout() {
  stopPolling()
  authed.value = false
  token.value = ''
  tokenInput.value = ''
  setStoredToken('')
}

async function triggerScan() {
  try {
    const r = await apiFetch('/api/scan', { method: 'POST' }, token.value)
    if (!r.ok) {
      notify(r.error || '启动扫描失败', 'bad')
      return
    }
    notify('已启动全流程扫描')
    await loadState()
    startPolling()
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function addSource() {
  const url = newSourceUrl.value.trim()
  if (!url) return
  addingSource.value = true
  try {
    const r = await apiFetch('/api/sources', {
      method: 'POST',
      body: JSON.stringify({ action: 'add', kind: newSourceKind.value, url }),
    }, token.value)
    if (!r.ok) {
      notify(r.error || '添加失败', 'bad')
      return
    }
    sourceList.value = r.sources || []
    newSourceUrl.value = ''
    const item = r.item
    notify(item?.ok ? `已添加并验证通过（${item.count} 条）` : `已添加，但拉取失败：${item?.message}`, item?.ok ? 'ok' : 'bad')
  } catch (e) {
    notify(e.message, 'bad')
  } finally {
    addingSource.value = false
  }
}

function modeOf(s) {
  if (s.mode) return s.mode
  if (s.kind === '兜底订阅') return 'fallback'
  if (s.kind === '反代 ProxyIP' || s.kind === '反代订阅') return 'proxy'
  return 'vless'
}

async function refreshSource(s) {
  const mode = modeOf(s)
  refreshingUrl.value = s.target
  try {
    const r = await apiFetch('/api/sources', {
      method: 'POST',
      body: JSON.stringify({ action: 'refresh', mode, url: s.target }),
    }, token.value)
    if (r.ok) {
      sourceList.value = r.sources || []
      notify(r.item?.ok ? `已刷新：${r.item.message}` : `刷新失败：${r.item?.message}`, r.item?.ok ? 'ok' : 'bad')
    }
  } catch (e) {
    notify(e.message, 'bad')
  } finally {
    refreshingUrl.value = ''
  }
}

async function removeSource(s) {
  const mode = modeOf(s)
  try {
    const r = await apiFetch('/api/sources', {
      method: 'POST',
      body: JSON.stringify({ action: 'remove', mode, url: s.target }),
    }, token.value)
    if (r.ok) {
      sourceList.value = r.sources || []
      notify('已移除订阅源')
    }
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function copySub(url) {
  try {
    await copyText(url)
    notify('已复制到剪贴板')
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function saveConfig() {
  const values = {}
  for (const g of schema.value) {
    for (const f of g.fields) {
      const raw = formValues[f.key]
      if (f.type === 'int') values[f.key] = parseInt(raw, 10) || 0
      else if (f.type === 'float') values[f.key] = parseFloat(raw) || 0
      else if (f.type === 'bool') values[f.key] = Boolean(raw)
      else if (f.type === 'list') values[f.key] = String(raw || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean)
      else values[f.key] = String(raw ?? '').trim()
    }
  }
  try {
    const r = await apiFetch('/api/config', { method: 'POST', body: JSON.stringify({ values }) }, token.value)
    if (!r.ok) {
      notify(r.error || '保存失败', 'bad')
      return
    }
    notify('设置已保存并同步刷新订阅源状态')
    await loadAll()
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function resetConfig() {
  try {
    await apiFetch('/api/config', { method: 'POST', body: JSON.stringify({ reset: true }) }, token.value)
    notify('已恢复内置默认配置')
    await loadAll()
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function saveWb() {
  try {
    const payload = { ...wb.value, password: wbPass.value }
    const r = await apiFetch('/api/writeback', { method: 'POST', body: JSON.stringify(payload) }, token.value)
    wbPass.value = ''
    if (r.ok) {
      wb.value = r.writeback
      notify('备份设置已保存')
    }
  } catch (e) {
    notify(e.message, 'bad')
  }
}

async function syncWb() {
  try {
    const r = await apiFetch('/api/writeback/sync', { method: 'POST' }, token.value)
    notify(r.result?.message || r.error || (r.ok ? '备份成功' : '备份失败'), r.ok ? 'ok' : 'bad')
    const wbRes = await apiFetch('/api/writeback', {}, token.value)
    if (wbRes?.ok) wb.value = wbRes.writeback
  } catch (e) {
    notify(e.message, 'bad')
  }
}

onMounted(() => {
  connect()
})

onBeforeUnmount(() => {
  stopPolling()
})
</script>

<template>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <h1>warp-sub</h1>
        <span class="badge">VLESS 优选订阅</span>
        <span v-if="authed && state?.ech_enabled" class="badge" :class="state?.ech_ready ? 'ok' : 'warn'">
          ECH {{ state?.ech_ready ? '已就绪' : '自动获取' }}
        </span>
        <span v-if="authed && state?.proxy_ip" class="badge ok">反代: {{ state.proxy_ip }}</span>
      </div>
      <span v-if="authed" class="badge" :class="state?.running ? 'warn' : 'ok'">
        {{ progressText }}
      </span>
      <div class="spacer" />
      <template v-if="authed">
        <button class="btn primary" :disabled="state?.running" @click="triggerScan">
          {{ state?.running ? '扫描中…' : '立即扫描' }}
        </button>
        <button class="btn" @click="logout">退出</button>
      </template>
    </header>

    <div v-if="!authed" class="login-box">
      <div class="card">
        <div class="card-title">访问验证</div>
        <div class="field">
          <label>访问令牌（未配置留空直接连接）</label>
          <input v-model="tokenInput" type="password" placeholder="WARPSUB_TOKEN" @keyup.enter="connect" />
        </div>
        <div class="row" style="margin-top: 14px">
          <button class="btn primary" @click="connect">连接面板</button>
        </div>
        <p v-if="loginErr" class="muted" style="color: var(--bad); margin-top: 10px">{{ loginErr }}</p>
      </div>
    </div>

    <template v-else>
      <nav class="nav-tabs">
        <button class="nav-tab" :class="{ active: activeTab === 'overview' }" @click="activeTab = 'overview'">
          概览与节点
        </button>
        <button class="nav-tab" :class="{ active: activeTab === 'sources' }" @click="activeTab = 'sources'">
          订阅源 ({{ sourceList.length }})
        </button>
        <button class="nav-tab" :class="{ active: activeTab === 'history' }" @click="activeTab = 'history'">
          历史趋势
        </button>
        <button class="nav-tab" :class="{ active: activeTab === 'config' }" @click="activeTab = 'config'">
          设置
        </button>
      </nav>

      <main class="main">
        <template v-if="activeTab === 'overview'">
          <section class="kpi-grid">
            <div class="kpi">
              <div class="kpi-label">可用节点</div>
              <div class="kpi-value">{{ state?.passed ?? 0 }} / {{ state?.candidates ?? 0 }}</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">Worker 域名</div>
              <div class="kpi-value" style="font-size: 14px; word-break: break-all">{{ state?.worker_host || '-' }}</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">上次更新</div>
              <div class="kpi-value" style="font-size: 14px">{{ state?.generated_at ? state.generated_at.slice(0, 19).replace('T', ' ') : '从未' }}</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">下次定时更新</div>
              <div class="kpi-value" style="font-size: 14px">{{ state?.next_scan_at || '-' }}</div>
            </div>
          </section>

          <section class="card">
            <div class="card-title">订阅链接（客户端导入一次即可，每日自动更新）</div>
            <div class="sub-row">
              <span class="badge ok">Clash / mihomo</span>
              <code>{{ subUrls.clash }}</code>
              <button class="btn" @click="copySub(subUrls.clash)">复制</button>
            </div>
            <div class="sub-row" style="margin-bottom: 0">
              <span class="badge ok">v2rayA / Base64</span>
              <code>{{ subUrls.v2ray }}</code>
              <button class="btn" @click="copySub(subUrls.v2ray)">复制</button>
            </div>
          </section>

          <section class="card">
            <div class="card-title">
              <span>优选节点 ({{ vlessNodes.length }})</span>
              <span class="muted">耗时 {{ state?.duration_sec ? Math.round(state.duration_sec) + 's' : '-' }}</span>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>节点</th>
                    <th class="num">延迟</th>
                    <th class="num">抖动</th>
                    <th class="num">速率 (均/峰)</th>
                    <th>出口</th>
                    <th>AI / 地域</th>
                    <th class="num">评分</th>
                    <th class="num">连续</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-if="!vlessNodes.length">
                    <td colspan="8" class="muted">暂无可用节点，请点击右上角「立即扫描」</td>
                  </tr>
                  <tr v-for="n in vlessNodes" :key="n.server + ':' + n.port">
                    <td>
                      <div>{{ n.server }}:{{ n.port }}</div>
                      <div class="muted" style="font-size: 11px">{{ n.resolved_ip }}</div>
                    </td>
                    <td class="num">{{ Math.round(n.latency_ms) }}ms</td>
                    <td class="num">{{ Math.round(n.jitter_ms) }}ms</td>
                    <td class="num">
                      <span v-if="n.speed_mbps">{{ n.speed_mbps }}M / {{ n.speed_peak_mbps }}M</span>
                      <span v-else class="muted">未测</span>
                    </td>
                    <td>
                      <span v-if="n.egress_country" class="badge" :title="`${n.egress_ip} ${n.egress_city}`">
                        {{ n.egress_country }}
                      </span>
                      <span v-else class="muted">-</span>
                    </td>
                    <td>
                      <span
                        class="badge"
                        :class="aiStatus(n).ok === true ? 'ok' : (aiStatus(n).ok === false ? 'bad' : '')"
                        :title="aiStatus(n).detail"
                      >
                        {{ aiStatus(n).label }}
                      </span>
                    </td>
                    <td class="num"><b>{{ n.score }}</b></td>
                    <td class="num">{{ n.streak || 1 }}次</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section v-if="fallbackNodes.length" class="card">
            <div class="card-title">
              <span>🛡️ 兜底备用节点 ({{ fallbackNodes.length }})</span>
              <span class="muted">开源订阅兜底 · 主节点不可用时自动切换</span>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>协议</th>
                    <th>名称</th>
                    <th>服务器</th>
                    <th class="num">延迟</th>
                    <th class="num">评分</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(n, idx) in fallbackNodes" :key="idx">
                    <td><span class="badge warn">{{ (n.proto || 'proxy').toUpperCase() }}</span></td>
                    <td>{{ n.name }}</td>
                    <td>{{ n.server }}:{{ n.port }}</td>
                    <td class="num">{{ n.latency_ms ? Math.round(n.latency_ms) + 'ms' : '-' }}</td>
                    <td class="num"><b>{{ n.score }}</b></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section v-if="state?.rejected?.length" class="card">
            <div class="card-title">淘汰记录 ({{ state.rejected.length }})</div>
            <div class="table-wrap" style="max-height: 320px; overflow-y: auto">
              <table>
                <thead>
                  <tr>
                    <th>类型</th>
                    <th>节点</th>
                    <th class="num">延迟</th>
                    <th class="num">丢包</th>
                    <th>淘汰原因</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(r, idx) in state.rejected" :key="idx">
                    <td><span class="badge bad">{{ (r.class || 'vless').toUpperCase() }}</span></td>
                    <td>{{ r.server }}:{{ r.port }}</td>
                    <td class="num">{{ r.latency_ms ? Math.round(r.latency_ms) + 'ms' : '-' }}</td>
                    <td class="num">{{ r.loss_pct ?? '-' }}%</td>
                    <td class="muted">{{ r.reason }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </template>

        <template v-if="activeTab === 'sources'">
          <section class="card">
            <div class="card-title">添加订阅源（提交后立即拉取并验证有效性）</div>
            <div class="row">
              <select
                v-model="newSourceKind"
                style="padding: 9px 11px; background: #0b0f14; border: 1px solid var(--border); border-radius: 8px; color: var(--fg)"
              >
                <option value="vless_ip">优选 IP 源</option>
                <option value="vless_domain">优选域名源</option>
                <option value="proxy">反代 ProxyIP 源</option>
                <option value="fallback">兜底免费订阅</option>
              </select>
              <input
                v-model="newSourceUrl"
                type="text"
                style="flex: 1; min-width: 260px"
                placeholder="https://... （支持 TXT 列表、Base64、URI 分享链接、Clash YAML）"
                @keyup.enter="addSource"
              />
              <button class="btn primary" :disabled="addingSource || !newSourceUrl.trim()" @click="addSource">
                {{ addingSource ? '验证中…' : '添加并验证' }}
              </button>
            </div>
          </section>

          <section class="card">
            <div class="card-title">
              <span>订阅源与反代实时状态</span>
              <span class="muted">随定时任务自动更新，也可单条即时刷新</span>
            </div>
            <div v-if="!sourceList.length" class="muted">暂无订阅源记录</div>
            <div v-else class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>类型</th>
                    <th>源地址 / 目标</th>
                    <th>状态</th>
                    <th class="num">解析数</th>
                    <th class="num">耗时</th>
                    <th>详情</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(s, idx) in sourceList" :key="idx">
                    <td><span class="badge">{{ s.kind }}</span></td>
                    <td style="max-width: 340px; overflow: hidden; text-overflow: ellipsis" :title="s.target">{{ s.target }}</td>
                    <td>
                      <span class="badge" :class="s.ok ? 'ok' : 'bad'">{{ s.ok ? '有效' : '失效' }}</span>
                    </td>
                    <td class="num">{{ s.count ?? 0 }}</td>
                    <td class="num">{{ s.ms ? s.ms + 'ms' : '-' }}</td>
                    <td class="muted">{{ s.message }}</td>
                    <td>
                      <div v-if="s.target && (s.target.startsWith('http://') || s.target.startsWith('https://'))" class="row" style="gap: 6px; flex-wrap: nowrap">
                        <button class="btn" style="padding: 4px 10px" :disabled="refreshingUrl === s.target" @click="refreshSource(s)">
                          {{ refreshingUrl === s.target ? '…' : '刷新' }}
                        </button>
                        <button class="btn danger" style="padding: 4px 10px" @click="removeSource(s)">删除</button>
                      </div>
                      <span v-else class="muted">内置</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </template>

        <template v-if="activeTab === 'history'">
          <section class="card">
            <div class="card-title">最近 30 次扫描趋势</div>
            <div v-if="!history.length" class="muted">暂无历史记录</div>
            <template v-else>
              <div class="muted" style="margin-bottom: 4px">最优延迟 (ms)</div>
              <svg viewBox="0 0 600 90" preserveAspectRatio="none" style="width: 100%; height: 90px; margin-bottom: 14px">
                <path :d="latencySpark" fill="none" stroke="#4c9aff" stroke-width="2" stroke-linejoin="round" />
              </svg>
              <div class="muted" style="margin-bottom: 4px">入选节点数</div>
              <svg viewBox="0 0 600 90" preserveAspectRatio="none" style="width: 100%; height: 90px">
                <path :d="passedSpark" fill="none" stroke="#3fb950" stroke-width="2" stroke-linejoin="round" />
              </svg>
            </template>
          </section>

          <section class="card">
            <div class="card-title">扫描明细</div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th class="num">候选</th>
                    <th class="num">入选</th>
                    <th class="num">最优延迟</th>
                    <th class="num">平均延迟</th>
                    <th class="num">最快速率</th>
                    <th class="num">耗时</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="h in [...history].reverse().slice(0, 30)" :key="h.at">
                    <td>{{ h.at }}</td>
                    <td class="num">{{ h.candidates }}</td>
                    <td class="num">{{ h.passed }}</td>
                    <td class="num">{{ h.best_latency_ms }}ms</td>
                    <td class="num">{{ h.avg_latency_ms }}ms</td>
                    <td class="num">{{ h.best_speed_mbps ? h.best_speed_mbps + 'M' : '-' }}</td>
                    <td class="num">{{ h.duration_sec }}s</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </template>

        <template v-if="activeTab === 'config'">
          <section v-if="Object.keys(envOverrides).length" class="card">
            <div class="card-title">环境变量覆盖（只读）</div>
            <div class="row">
              <span v-for="(val, k) in envOverrides" :key="k" class="badge">{{ k }}={{ val }}</span>
            </div>
          </section>

          <section v-for="g in schema" :key="g.title" class="card">
            <div class="card-title">{{ g.title }}</div>
            <div class="form-grid">
              <div v-for="f in g.fields" :key="f.key" class="field">
                <label v-if="f.type !== 'bool'">{{ f.label }}</label>
                <div v-if="f.type === 'bool'" class="check-field">
                  <input :id="f.key" v-model="formValues[f.key]" type="checkbox" />
                  <label :for="f.key" style="margin: 0">{{ f.label }}</label>
                </div>
                <textarea v-else-if="f.type === 'list'" v-model="formValues[f.key]" rows="3" />
                <input
                  v-else-if="f.type === 'int' || f.type === 'float'"
                  v-model="formValues[f.key]"
                  type="number"
                  :step="f.type === 'float' ? '0.01' : '1'"
                />
                <input v-else v-model="formValues[f.key]" type="text" />
                <div v-if="f.help" class="help">{{ f.help }}</div>
              </div>
            </div>
          </section>

          <div class="row">
            <button class="btn primary" @click="saveConfig">保存设置</button>
            <button class="btn danger" @click="resetConfig">恢复默认</button>
          </div>

          <section v-if="wb" class="card">
            <div class="card-title">
              <span>Worker 备份回写（可选）</span>
              <span class="muted">将最优节点同步写入 Worker ADD.txt，防止本机离线后订阅失效</span>
            </div>
            <div class="form-grid">
              <div class="field">
                <label>Worker 后台地址（留空自动复用 Worker 域名）</label>
                <input
                  v-model="wb.base_url"
                  type="text"
                  :placeholder="wb.effective_url || 'https://your-worker.workers.dev'"
                />
              </div>
              <div class="field">
                <label>Worker 后台密码</label>
                <input v-model="wbPass" type="password" :placeholder="wb.has_password ? '已保存，留空则不修改' : '后台密码'" />
              </div>
              <div class="field">
                <div class="check-field">
                  <input id="wbEn" v-model="wb.enabled" type="checkbox" />
                  <label for="wbEn" style="margin: 0">启用备份</label>
                </div>
                <div class="check-field" style="padding-top: 8px">
                  <input id="wbAu" v-model="wb.auto" type="checkbox" />
                  <label for="wbAu" style="margin: 0">扫描后自动备份</label>
                </div>
              </div>
            </div>
            <div class="row" style="margin-top: 14px">
              <button class="btn" @click="saveWb">保存备份设置</button>
              <button class="btn primary" @click="syncWb">立即备份到 Worker</button>
              <span v-if="wb.last?.at" class="muted">{{ wb.last.at }} · {{ wb.last.message }}</span>
            </div>
          </section>
        </template>
      </main>
    </template>

    <div v-if="toast.show" class="toast" :class="toast.type">{{ toast.text }}</div>
  </div>
</template>
