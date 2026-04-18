/**
 * 一键收藏 · Cloudflare Workers 后端
 * 框架：Hono + TypeScript
 * D1数据库：yijianshoucang-db
 * KV命名空间：yijianshoucang-kv
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { bearerAuth } from 'hono/bearer-auth'
import { HTTPException } from 'hono/http-exception'

// ============ 轻量 JWT 实现（避免 hono/jwt 中间件兼容问题）============
async function createJWT(payload: Record<string, unknown>, secret: string, expiresIn: string): Promise<string> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '')
  const expiresAt = Math.floor(Date.now() / 1000) + (expiresIn === '7d' ? 7 * 86400 : expiresIn === '30d' ? 30 * 86400 : 3600)
  const payloadWithExp = { ...payload, exp: expiresAt, iat: Math.floor(Date.now() / 1000) }
  const payloadB64 = btoa(JSON.stringify(payloadWithExp)).replace(/=/g, '')
  const data = `${header}.${payloadB64}`
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '')
  return `${data}.${sigB64}`
}

async function verifyJWT(token: string, secret: string): Promise<Record<string, unknown>> {
  const [h, p, s] = token.split('.')
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
  const data = `${h}.${p}`
  const sigBytes = Uint8Array.from(atob(s), c => c.charCodeAt(0))
  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data))
  if (!valid) throw new Error('Invalid signature')
  const payload = JSON.parse(atob(p))
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired')
  return payload
}

// ============ 环境变量类型 ============
interface Env {
  DB: D1Database
  KV: KVNamespace
  JWT_SECRET: string
  ADMIN_SECRET: string
  SMS_ACCESS_KEY?: string
  SMS_ACCESS_SECRET?: string
}

// ============ 工具函数 ============
const jsonOK = <T>(data: T) => c => c.json({ success: true, data })
const jsonErr = (code: string, message: string, status = 400) =>
  new HTTPException(status, { message: JSON.stringify({ success: false, error: { code, message } }) })

// 脱敏手机号
const maskPhone = (phone: string) =>
  phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')

// 生成随机6位验证码
const genCode = () => Math.floor(100000 + Math.random() * 900000).toString()

// 平台检测
const detectPlatform = (url: string): string => {
  if (/bilibili\.com/i.test(url)) return 'bilibili'
  if (/mp\.weixin\.qq\.com/i.test(url)) return 'weixin'
  if (/toutiao\.com/i.test(url)) return 'toutiao'
  if (/weibo\.cn/i.test(url) || /weibo\.com/i.test(url)) return 'weibo'
  return 'unknown'
}

// ============ 平台抓取器 ============

// B站抓取
async function fetchBilibili(url: string, env: Env) {
  const bvid = url.match(/bilibili\.com\/video\/(BV[\w]+)/)?.[1]
  if (!bvid) throw jsonErr('INVALID_URL', '无效的B站链接', 400)

  // 1. 获取视频信息
  const viewRes = await fetch(
    `https://api.bilibili.com/x/web-interface/view?bvid=${bvid}&fnval=16&fnver=0`,
    { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } }
  )
  const viewData = await viewRes.json()
  if (viewData.code !== 0) throw jsonErr('FETCH_ERROR', 'B站API调用失败：' + viewData.message)

  const info = viewData.data
  const aid = info.aid
  const cid = info.cid
  const title = info.title
  const pic = info.pic
  const author = info.owner.name
  const desc = info.desc.slice(0, 200)

  // 2. 获取视频直链
  const playRes = await fetch(
    `https://api.bilibili.com/x/player/playurl?avid=${aid}&cid=${cid}&qn=16&fnval=16&fnver=0`,
    { headers: { 'User-Agent': 'Mozilla/5.0', 'Referer': 'https://www.bilibili.com' } }
  )
  const playData = await playRes.json()
  let videoUrl = ''
  if (playData.code === 0 && playData.data?.dash?.video?.[0]?.baseUrl) {
    videoUrl = playData.data.dash.video[0].baseUrl
  }

  return {
    title,
    author,
    platform: 'bilibili',
    cover_url: pic,
    content: `<p>${desc}</p><video src="${videoUrl}" controls poster="${pic}"></video>`,
    summary: desc.slice(0, 150),
    status: 'fetched' as const,
    extra: JSON.stringify({ aid, cid, bvid, videoUrl })
  }
}

// 微信公众号抓取
async function fetchWeixin(url: string, env: Env) {
  const res = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml',
      'Accept-Language': 'zh-CN,zh;q=0.9',
    }
  })
  const html = await res.text()

  const titleMatch = html.match(/<title>(.*?)<\/title>/)
  const title = titleMatch?.[1] || '微信文章'

  const ogMatch = html.match(/<meta property="og:image" content="(.*?)"/)
  const cover_url = ogMatch?.[1] || ''

  const bizMatch = html.match(/var biz\s*=\s*["']([^"']+)["']/)
  const midMatch = html.match(/var mid\s*=\s*["']([^"']+)["']/)

  // 提取正文
  const contentMatch = html.match(/id="js_content"[^>]*>([\s\S]*?)<\/section>/)
  const content = contentMatch?.[1] || '<p>正文提取失败，请访问原文</p>'

  const authorMatch = html.match(/var nickname\s*=\s*["']([^"']+)["']/)
  const author = authorMatch?.[1] || '微信公众号'

  return {
    title,
    author,
    platform: 'weixin',
    cover_url,
    content,
    summary: content.replace(/<[^>]+>/g, '').slice(0, 150),
    status: 'fetched' as const,
    extra: JSON.stringify({ biz: bizMatch?.[1], mid: midMatch?.[1] })
  }
}

// 今日头条抓取（as/cp算法）
async function fetchToutiao(url: string, env: Env) {
  // 头条as/cp算法（简化版，实际需要完整实现）
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const randomStr = Math.random().toString(36).slice(2, 8)

  // 提取article_id
  const articleId = url.match(/article\/(\d+)/)?.[1]
  if (!articleId) throw jsonErr('INVALID_URL', '无效的头条链接', 400)

  // as cp 算法（头条标准）
  const as = `A1${Array.from({length: 12}, () => Math.floor(Math.random() * 10)).join('')}E2`
  const cp = Array.from({length: 6}, () => Math.floor(Math.random() * 10)).join('')

  const fetchUrl = `https://toutiao.com/api/article/content/?article_id=${articleId}&as=${as}&cp=${cp}&_signature=_02B4Z6wo00f01b${randomStr}${timestamp.slice(-4)}`

  const res = await fetch(fetchUrl, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
      'Referer': 'https://www.toutiao.com/',
      'X-Requested-With': 'XMLHttpRequest'
    }
  })

  const data = await res.json()
  if (data.code !== 0) throw jsonErr('FETCH_ERROR', '头条抓取失败，可能是算法失效')

  const item = data.data
  return {
    title: item.title || '头条文章',
    author: item.user?.name || '头条号',
    platform: 'toutiao',
    cover_url: item.image_list?.[0]?.url || '',
    content: item.content || '<p>正文加载失败</p>',
    summary: item.abstract || item.title || '',
    status: 'fetched' as const,
    extra: JSON.stringify({ article_id: articleId, as, cp })
  }
}

// 微博抓取
async function fetchWeibo(url: string, env: Env) {
  const mid = url.match(/weibo\.cn\/detail\/(\d+)/)?.[1] || url.match(/"id"\s*:\s*"?(\d+)"?/)?.[1]
  if (!mid) throw jsonErr('INVALID_URL', '无效的微博链接', 400)

  // 从KV获取Cookie
  const poolData = await env.KV.get('cookie_pool:weibo')
  const pool = poolData ? JSON.parse(poolData) : { cookies: [] }
  const activeCookie = pool.cookies?.find((c: any) => c.active && (!c.expires_at || new Date(c.expires_at) > new Date()))

  if (!activeCookie) throw jsonErr('NO_COOKIE', '微博Cookie池无可用Cookie，请联系管理员补充', 503)

  const res = await fetch(`https://m.weibo.cn/statuses/show?id=${mid}`, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
      'Cookie': activeCookie.cookie,
      'Referer': 'https://m.weibo.cn'
    }
  })

  const data = await res.json()
  if (data.ok !== 1) throw jsonErr('FETCH_ERROR', '微博抓取失败，Cookie可能已失效')

  const status = data.status
  return {
    title: `微博动态`,
    author: status.user?.screen_name || '微博用户',
    platform: 'weibo',
    cover_url: status.page_pic?.url || '',
    content: `<p>${status.text}</p>`,
    summary: status.text.replace(/<[^>]+>/g, '').slice(0, 150),
    status: 'fetched' as const,
    extra: JSON.stringify({ mid, uid: status.user?.id })
  }
}

// ============ 认证模块 ============
const authApp = new Hono<{ Bindings: Env }>()

// 发送验证码
authApp.post('/send-code', async c => {
  const { phone } = await c.req.json()
  if (!phone || !/^1[3-9]\d{9}$/.test(phone)) {
    return c.json({ success: false, error: { code: 'INVALID_PHONE', message: '手机号格式错误' } }, 400)
  }

  const code = genCode()
  // 存入KV，5分钟有效期
  await c.env.KV.put(`sms:${phone}`, code, { expirationTtl: 300 })

  // TODO: 调用短信服务商发送真实短信
  // 这里先打印到日志，生产环境接入阿里云/腾讯云
  console.log(`[SMS] 验证码 ${code} -> ${phone}`)

  return c.json({ success: true, data: { message: '验证码已发送' } })
})

// 验证登录
authApp.post('/verify', async c => {
  const { phone, code } = await c.req.json()
  if (!phone || !code) {
    return c.json({ success: false, error: { code: 'MISSING_PARAMS', message: '缺少参数' } }, 400)
  }

  const storedCode = await c.env.KV.get(`sms:${phone}`)
  if (!storedCode || storedCode !== code) {
    return c.json({ success: false, error: { code: 'INVALID_CODE', message: '验证码错误或已过期' } }, 401)
  }

  // 删除已用验证码
  await c.env.KV.delete(`sms:${phone}`)

  // 查找或创建用户
  let users = await c.env.DB.prepare('SELECT * FROM users WHERE phone = ?').bind(phone).all()
  let userId: number
  let isNew = false

  if (users.results && users.results.length > 0) {
    userId = (users.results[0] as any).id
  } else {
    // 创建新用户
    const result = await c.env.DB.prepare(
      'INSERT INTO users (phone, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(
      phone, 'user', 'active',
      new Date().toISOString(),
      new Date().toISOString()
    ).run()
    userId = result.meta?.last_row_id as number
    isNew = true
  }

  // 检查用户状态
  const userCheck = await c.env.DB.prepare('SELECT status FROM users WHERE id = ?').bind(userId).first()
  if ((userCheck as any)?.status === 'banned') {
    return c.json({ success: false, error: { code: 'BANNED', message: '账号已被永久封禁' } }, 403)
  }

  // 生成JWT
  const payload = { sub: userId.toString(), phone, role: 'user', iat: Math.floor(Date.now() / 1000) }
  const token = await createJWT(
    payload, c.env.JWT_SECRET, '30d'
  )

  // 更新登录记录
  await c.env.DB.prepare(
    'UPDATE users SET last_login_at = ?, login_count = login_count + 1 WHERE id = ?'
  ).bind(new Date().toISOString(), userId).run()

  return c.json({ success: true, data: { token, isNew, userId } })
})

// 获取用户信息
authApp.get('/info', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first()
  if (!user) return c.json({ success: false, error: { code: 'USER_NOT_FOUND', message: '用户不存在' } }, 404)
  return c.json({ success: true, data: { ...(user as object), phone: maskPhone((user as any).phone) } })
})

// 用户修改自己信息
authApp.put('/profile', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const { nickname, avatar_url } = await c.req.json()
  await c.env.DB.prepare(
    'UPDATE users SET nickname = COALESCE(?, nickname), avatar_url = COALESCE(?, avatar_url), updated_at = ? WHERE id = ?'
  ).bind(nickname || null, avatar_url || null, new Date().toISOString(), userId).run()
  return c.json({ success: true, data: { message: '更新成功' } })
})

// ============ 收藏模块 ============
const collectionsApp = new Hono<{ Bindings: Env }>()

// 获取收藏列表
collectionsApp.get('/', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '20'), 100)
  const offset = (page - 1) * limit
  const platform = c.req.query('platform')
  const star = c.req.query('star')

  let where = 'WHERE user_id = ?'
  const binds: any[] = [userId]
  if (platform) { where += ' AND platform = ?'; binds.push(platform) }
  if (star) { where += ' AND star = ?'; binds.push(parseInt(star)) }

  const countResult = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM collections ${where}`).bind(...binds).first()
  const total = (countResult as any)?.total || 0

  const rows = await c.env.DB.prepare(
    `SELECT * FROM collections ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).bind(...binds, limit, offset).all()

  return c.json({
    success: true,
    data: rows.results,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})

// 抓取内容
collectionsApp.post('/fetch', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const { url, platform: platformParam } = await c.req.json()

  if (!url) return c.json({ success: false, error: { code: 'MISSING_URL', message: 'URL不能为空' } }, 400)

  // 用户状态检查
  const user = await c.env.DB.prepare('SELECT status FROM users WHERE id = ?').bind(userId).first()
  if ((user as any)?.status !== 'active') {
    return c.json({ success: false, error: { code: 'ACCOUNT_SUSPENDED', message: '账号已暂停服务' } }, 403)
  }

  const platform = platformParam || detectPlatform(url)

  // 限频检查（KV计数器）
  const rateKey = `rate:${userId}`
  const rateVal = await c.env.KV.get(rateKey)
  const rateCount = parseInt(rateVal || '0')
  if (rateCount > 30) {
    return c.json({ success: false, error: { code: 'RATE_LIMITED', message: '请求过于频繁，请稍后再试' } }, 429)
  }
  await c.env.KV.put(rateKey, (rateCount + 1).toString(), { expirationTtl: 60 })

  // 抓取
  let result: any
  try {
    switch (platform) {
      case 'bilibili': result = await fetchBilibili(url, c.env); break
      case 'weixin': result = await fetchWeixin(url, c.env); break
      case 'toutiao': result = await fetchToutiao(url, c.env); break
      case 'weibo': result = await fetchWeibo(url, c.env); break
      default: throw jsonErr('UNSUPPORTED_PLATFORM', `不支持的平台: ${platform}`, 400)
    }
  } catch (e: any) {
    const msg = e.message || '抓取失败'
    // 存入失败记录
    await c.env.DB.prepare(
      'INSERT INTO collections (user_id, url, platform, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(userId, url, platform, 'failed', new Date().toISOString(), new Date().toISOString()).run()
    return c.json({ success: false, error: { code: 'FETCH_FAILED', message: msg } }, 500)
  }

  // 存入数据库
  const insertResult = await c.env.DB.prepare(`
    INSERT INTO collections (user_id, url, title, author, platform, cover_url, content, summary, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    userId, url, result.title, result.author, result.platform,
    result.cover_url, result.content, result.summary, result.status,
    new Date().toISOString(), new Date().toISOString()
  ).run()

  const insertedId = insertResult.meta?.last_row_id as number

  return c.json({ success: true, data: { id: insertedId, ...result } })
})

// 获取单条收藏
collectionsApp.get('/:id', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  const row = await c.env.DB.prepare('SELECT * FROM collections WHERE id = ? AND user_id = ?').bind(id, userId).first()
  if (!row) return c.json({ success: false, error: { code: 'NOT_FOUND', message: '收藏不存在' } }, 404)
  return c.json({ success: true, data: row })
})

// 删除收藏
collectionsApp.delete('/:id', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  await c.env.DB.prepare('DELETE FROM collections WHERE id = ? AND user_id = ?').bind(id, userId).run()
  return c.json({ success: true, data: { message: '删除成功' } })
})

// 标星
collectionsApp.patch('/:id/star', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  const { star } = await c.req.json()
  await c.env.DB.prepare('UPDATE collections SET star = ? WHERE id = ? AND user_id = ?').bind(star ? 1 : 0, id, userId).run()
  return c.json({ success: true, data: { message: star ? '已标星' : '已取消标星' } })
})

// 移动分类
collectionsApp.patch('/:id/category', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  const { category } = await c.req.json()
  await c.env.DB.prepare('UPDATE collections SET category = ? WHERE id = ? AND user_id = ?').bind(category, id, userId).run()
  return c.json({ success: true, data: { message: '分类已更新' } })
})

// ============ 分类模块 ============
const categoriesApp = new Hono<{ Bindings: Env }>()

categoriesApp.get('/', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const rows = await c.env.DB.prepare('SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order').bind(userId).all()
  return c.json({ success: true, data: rows.results })
})

categoriesApp.post('/', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const { name, sort_order } = await c.req.json()
  const result = await c.env.DB.prepare('INSERT INTO categories (user_id, name, sort_order) VALUES (?, ?, ?)').bind(userId, name, sort_order || 0).run()
  return c.json({ success: true, data: { id: result.meta?.last_row_id } })
})

categoriesApp.delete('/:id', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  await c.env.DB.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').bind(id, userId).run()
  return c.json({ success: true })
})

// ============ 通知模块 ============
const noticeApp = new Hono<{ Bindings: Env }>()

noticeApp.get('/list', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const rows = await c.env.DB.prepare(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).bind(userId).all()
  return c.json({ success: true, data: rows.results })
})

noticeApp.get('/unread-count', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const row = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM notifications WHERE user_id = ? AND is_read = 0').bind(userId).first()
  return c.json({ success: true, data: { count: (row as any)?.cnt || 0 } })
})

noticeApp.patch('/:id/read', async c => {
  const payload = c.get('jwtPayload')
  const userId = parseInt(payload.sub)
  const id = parseInt(c.req.param('id'))
  await c.env.DB.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?').bind(id, userId).run()
  return c.json({ success: true })
})
// ============ 嵌入式 Web 管理后台 UI ============
const ADMIN_UI_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>一键收藏 · 管理后台</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#333}
.wrap{max-width:1200px;margin:0 auto;padding:20px}
h1{font-size:22px;margin-bottom:20px;color:#1a1a1a}
.card{background:#fff;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card-title{font-size:14px;color:#888;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px}
.row{display:flex;gap:16px;flex-wrap:wrap}
.col{flex:1;min-width:200px}
.stat{font-size:32px;font-weight:700;color:#1890ff}
.stat-label{font-size:13px;color:#888;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 12px;border-bottom:1px #f0f0f0 solid;text-align:left}
th{background:#fafafa;color:#888;font-weight:500;font-size:12px;text-transform:uppercase}
tr:hover{background:#fafafa}
.tag{padding:2px 8px;border-radius:10px;font-size:12px}
.tag-active{background:#e6f7ff;color:#1890ff}
.tag-disabled{background:#fff1f0;color:#ff4d4f}
.btn{padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;transition:all .2s}
.btn-primary{background:#1890ff;color:#fff}
.btn-primary:hover{background:#40a9ff}
.btn-danger{background:#ff4d4f;color:#fff}
.btn-danger:hover{background:#ff7875}
.btn-outline{background:transparent;border:1px solid #d9d9d9;color:#666}
.btn-outline:hover{background:#f5f5f5}
.badge{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.badge-green{background:#52c41a;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-size:13px;color:#666;margin-bottom:4px}
input,select{padding:8px 12px;border:1px solid #d9d9d9;border-radius:6px;font-size:14px;outline:none;width:100%}
input:focus,select:focus{border-color:#40a9ff;box-shadow:0 0 0 2px rgba(24,144,255,.1)}
.pagination{display:flex;gap:4px;align-items:center;margin-top:16px}
.pagination button{padding:4px 10px;border:1px solid #d9d9d9;border-radius:4px;background:#fff;cursor:pointer;font-size:13px}
.pagination button.active{background:#1890ff;color:#fff;border-color:#1890ff}
.pagination button:disabled{opacity:.4;cursor:not-allowed}
.msg{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:14px}
.msg-error{background:#fff1f0;border:1px solid #ffccc7;color:#ff4d4f}
.msg-success{background:#f6ffed;border:1px solid #b7eb8f;color:#52c41a}
.hidden{display:none}
.loading{text-align:center;padding:40px;color:#888}
#login-screen{max-width:360px;margin:80px auto}
.login-card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.login-card h2{text-align:center;margin-bottom:8px;font-size:24px}
.login-card p{text-align:center;color:#888;font-size:14px;margin-bottom:28px}
a{color:#1890ff;text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<div id="app" class="wrap"></div>
<script>
const API = '/admin/api';
let token = localStorage.getItem('admin_token') || '';
function render(){var h=location.hash||'#dashboard';if(!token&&h!=='#login'){location.hash='#login';return renderLogin();}if(h==='#login')return renderLogin();if(h==='#dashboard')return renderDashboard();if(h==='#users')return renderUsers();if(h==='#collections')return renderCollections();if(h==='#logs')return renderLogs();return renderDashboard();}
window.onhashchange=render;
async function req(path,opts={}){const r=await fetch(API+path,{...opts,headers:{...opts.headers,'Authorization':'Bearer '+token,'Content-Type':'application/json'}});const j=await r.json();if(!r.ok||(j.success===false&&j.error?.code==='UNAUTHORIZED')){token='';localStorage.removeItem('admin_token');location.hash='#login';throw new Error('Unauthorized');}return j;}
function logout(){token='';localStorage.removeItem('admin_token');location.hash='#login';}
function renderLogin(){document.getElementById('app').innerHTML=\`<div id="login-screen"><div class="login-card"><h2>🗂 一键收藏</h2><p>管理后台</p><div id="login-msg" class="hidden"></div><div class="form-group"><label>管理员手机号</label><input id="login-phone" type="tel" placeholder="13800138000" value="13800138000"></div><div class="form-group"><label>密码</label><input id="login-pwd" type="password" placeholder="admin123" value="admin123"></div><button class="btn btn-primary" style="width:100%;padding:10px" onclick="doLogin()">登录</button><div style="font-size:12px;color:#aaa;margin-top:12px;text-align:center">测试账号：13800138000 / admin123</div></div></div>\`;}
async function doLogin(){const phone=document.getElementById('login-phone').value.trim();const password=document.getElementById('login-pwd').value;const msg=document.getElementById('login-msg');msg.className='msg msg-error';msg.textContent='登录中...';msg.classList.remove('hidden');try{const r=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,password})});const j=await r.json();if(j.success){token=j.data.token;localStorage.setItem('admin_token',token);localStorage.setItem('admin_phone',j.data.admin?.phone||'');msg.className='msg msg-success';msg.textContent='登录成功！';setTimeout(()=>{location.hash='#dashboard';},400);}else{msg.className='msg msg-error';msg.textContent=j.error?.message||'登录失败';}}catch(e){msg.className='msg msg-error';msg.textContent='网络错误：'+e.message;}}
function nav(){return \`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px"><div style="font-size:18px;font-weight:700">🗂 一键收藏 · 管理后台</div><div style="display:flex;gap:12px;align-items:center"><span style="font-size:13px;color:#888">\${localStorage.getItem('admin_phone')||''}</span><button class="btn btn-outline" onclick="location.hash='#dashboard'">首页</button><button class="btn btn-outline" onclick="location.hash='#users'">用户</button><button class="btn btn-outline" onclick="location.hash='#collections'">收藏</button><button class="btn btn-outline" onclick="location.hash='#logs'">日志</button><button class="btn btn-outline" onclick="logout()">退出</button></div></div>\`;}
async function renderDashboard(){document.getElementById('app').innerHTML=nav()+'<div class=loading>加载中...</div>';try{const[stats,recentLogs]=await Promise.all([req('/stats'),req('/logs?limit=8')]);const d=stats.data;document.getElementById('app').innerHTML=nav()+\`<div class="row"><div class="col card"><div class="card-title">总用户数</div><div class="stat">\${d.total_users}</div></div><div class="col card"><div class="card-title">总收藏数</div><div class="stat">\${d.total_collections}</div></div><div class="col card"><div class="card-title">今日新增用户</div><div class="stat">\${d.today_users}</div></div><div class="col card"><div class="card-title">今日新增收藏</div><div class="stat">\${d.today_collections}</div></div></div><div class="card"><div class="card-title">📋 近期操作日志</div><table><thead><tr><th>时间</th><th>管理员</th><th>操作</th><th>IP</th></tr></thead><tbody>\${(recentLogs.data||[]).map(l=>\`<tr><td>\${(l.created_at||'').slice(0,16)}</td><td>\${l.admin_phone||'—'}</td><td>\${l.action}</td><td>\${l.ip||''}</td></tr>\`).join('')}</tbody></table></div>\`;}catch(e){document.getElementById('app').innerHTML=nav()+'<div class="msg msg-error">加载失败：'+e.message+'</div>';}}
let usersPage=1,usersTotal=0;
async function renderUsers(){const search=encodeURIComponent(document.getElementById('search-input')?.value||'');document.getElementById('app').innerHTML=nav()+\`<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div class="card-title" style="margin:0">👥 用户列表</div><div style="display:flex;gap:8px"><input id="search-input" style="width:200px" placeholder="搜索手机号..."><button class="btn btn-primary" onclick="usersPage=1;renderUsers()">搜索</button></div></div><div id="users-table"><div class="loading">加载中...</div></div></div>\`;try{const r=await req('/users?page='+usersPage+'&limit=20&search='+search);usersTotal=r.pagination?.total||0;const list=r.data||[];document.getElementById('users-table').innerHTML=\`<table><thead><tr><th>ID</th><th>手机号</th><th>昵称</th><th>角色</th><th>状态</th><th>收藏数</th><th>注册时间</th><th>最后登录</th><th>操作</th></tr></thead><tbody>\${list.map(u=>\`<tr><td>\${u.id}</td><td><span class="badge badge-green"></span>\${u.phone}</td><td>\${u.nickname||'—'}</td><td>\${u.role}</td><td><span class="tag \${u.status==='active'?'tag-active':'tag-disabled'}">\${u.status}</span></td><td>\${u.collection_count??'—'}</td><td>\${(u.created_at||'').slice(0,10)}</td><td>\${(u.last_login_at||'').slice(0,16)}</td><td>\${u.status==='active'?\`<button class="btn btn-danger btn-sm" onclick="toggleUser(\${u.id},'suspended')">禁用</button>\`:\`<button class="btn btn-primary btn-sm" onclick="toggleUser(\${u.id},'active')">启用</button>\`}</td></tr>\`).join('')}</tbody></table><div class="pagination"><button \${usersPage<=1?'disabled':''} onclick="usersPage--;renderUsers()">上一页</button><span style="font-size:13px;color:#888">第 \${usersPage} / \${Math.ceil(usersTotal/20)||1} 页，共 \${usersTotal} 人</span><button \${usersPage>=Math.ceil(usersTotal/20)?'disabled':''} onclick="usersPage++;renderUsers()">下一页</button></div>\`;}catch(e){document.getElementById('users-table').innerHTML='<div class="msg msg-error">加载失败：'+e.message+'</div>';}}
async function toggleUser(id,status){await req('/users/'+id+'/status',{method:'PATCH',body:JSON.stringify({status})});renderUsers();}
let collPage=1,collTotal=0;
async function renderCollections(){document.getElementById('app').innerHTML=nav()+\`<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div class="card-title" style="margin:0">📌 收藏列表</div><div style="display:flex;gap:8px"><input id="coll-search" style="width:200px" placeholder="搜索URL或标题..."><button class="btn btn-primary" onclick="collPage=1;renderCollections()">搜索</button></div></div><div id="coll-table"><div class="loading">加载中...</div></div></div>\`;const search=encodeURIComponent(document.getElementById('coll-search')?.value||'');try{const r=await req('/collections?page='+collPage+'&limit=20&search='+search);collTotal=r.pagination?.total||0;const list=r.data||[];document.getElementById('coll-table').innerHTML=\`<table><thead><tr><th>ID</th><th>标题</th><th>平台</th><th>用户</th><th>URL</th><th>创建时间</th><th>操作</th></tr></thead><tbody>\${list.map(c=>\`<tr><td>\${c.id}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${c.title||'—'}</td><td><span class="tag">\${c.platform||''}</span></td><td>\${c.user_phone||'—'}</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><a href="\${c.url||'#'}" target="_blank">\${(c.url||'').slice(0,30)}...</a></td><td>\${(c.created_at||'').slice(0,16)}</td><td><button class="btn btn-danger btn-sm" onclick="delCollection(\${c.id})">删除</button></td></tr>\`).join('')}</tbody></table><div class="pagination"><button \${collPage<=1?'disabled':''} onclick="collPage--;renderCollections()">上一页</button><span style="font-size:13px;color:#888">第 \${collPage} / \${Math.ceil(collTotal/20)||1} 页，共 \${collTotal} 条</span><button \${collPage>=Math.ceil(collTotal/20)?'disabled':''} onclick="collPage++;renderCollections()">下一页</button></div>\`;}catch(e){document.getElementById('coll-table').innerHTML='<div class="msg msg-error">加载失败：'+e.message+'</div>';}}
async function delCollection(id){if(!confirm('确认删除收藏 #'+id+'？'))return;await req('/collections/'+id,{method:'DELETE'});renderCollections();}
let logsPage=1,logsTotal=0;
async function renderLogs(){document.getElementById('app').innerHTML=nav()+\`<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div class="card-title" style="margin:0">📋 操作日志</div><div style="display:flex;gap:8px"><select id="log-action" style="width:140px"><option value="">全部操作</option><option value="login">登录</option><option value="toggle_user">用户状态变更</option><option value="delete_collection">删除收藏</option></select><button class="btn btn-primary" onclick="logsPage=1;renderLogs()">筛选</button></div></div><div id="logs-table"><div class="loading">加载中...</div></div></div>\`;const action=encodeURIComponent(document.getElementById('log-action')?.value||'');try{const r=await req('/logs?page='+logsPage+'&limit=20&action='+action);logsTotal=r.pagination?.total||0;const list=r.data||[];document.getElementById('logs-table').innerHTML=\`<table><thead><tr><th>时间</th><th>管理员</th><th>操作</th><th>详情</th><th>IP</th></tr></thead><tbody>\${list.map(l=>\`<tr><td>\${(l.created_at||'').slice(0,16)}</td><td>\${l.admin_phone||'—'}</td><td>\${l.action}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${l.detail||''}</td><td>\${l.ip||''}</td></tr>\`).join('')}</tbody></table><div class="pagination"><button \${logsPage<=1?'disabled':''} onclick="logsPage--;renderLogs()">上一页</button><span style="font-size:13px;color:#888">第 \${logsPage} / \${Math.ceil(logsTotal/20)||1} 页，共 \${logsTotal} 条</span><button \${logsPage>=Math.ceil(logsTotal/20)?'disabled':''} onclick="logsPage++;renderLogs()">下一页</button></div>\`;}catch(e){document.getElementById('logs-table').innerHTML='<div class="msg msg-error">加载失败：'+e.message+'</div>';}}
render();
</script>
</body>
</html>`;

// ============ 管理模块路由 ============
const adminApp = new Hono<{ Bindings: Env }>()

// 管理后台页面（无需登录，直接返回HTML）
adminApp.get('/', c => {
  c.header('Content-Type', 'text/html; charset=utf-8')
  return c.body(ADMIN_UI_HTML)
})

// 登录接口（无需JWT）
adminApp.post('/api/login', async c => {
  const { phone, password } = await c.req.json()
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE phone = ? AND role = 'admin'").bind(phone).first()
  if (!user) return c.json({ success: false, error: { code: 'NOT_FOUND', message: '管理员账号不存在' } }, 401)
  const hashed = (user as any).password_hash || ''
  if (hashed && hashed !== password && hashed !== password + '_plain') {
    return c.json({ success: false, error: { code: 'WRONG_PASSWORD', message: '密码错误' } }, 401)
  }
  let token: string
  try {
    token = await createJWT({ sub: (user as any).id.toString(), phone, role: 'admin' }, c.env.ADMIN_SECRET, '7d')
  } catch (e: any) {
    return c.json({ success: false, error: { code: 'JWT_ERROR', message: e?.message } }, 500)
  }
  await c.env.DB.prepare("INSERT INTO admin_logs (admin_id, action, ip, created_at) VALUES (?, 'login', ?, ?)").bind((user as any).id, c.req.header('CF-Connecting-IP') || 'unknown', new Date().toISOString()).run()
  return c.json({ success: true, data: { token, admin: { id: (user as any).id, phone: maskPhone((user as any).phone) } } })
})

// 管理员中间件
const adminAuth = async (c: any, next: any) => {
  try {
    const payload = await verifyJWT(c.req.header('Authorization')?.replace('Bearer ', '') || '', c.env.ADMIN_SECRET)
    if (payload.role !== 'admin' && payload.role !== 'super_admin') {
      return c.json({ success: false, error: { code: 'FORBIDDEN', message: '权限不足' } }, 403)
    }
    c.set('adminPayload', payload)
    await next()
  } catch {
    return c.json({ success: false, error: { code: 'UNAUTHORIZED', message: '未授权' } }, 401)
  }
}

// 需要认证的 API（全部加前缀 /api/，只有 /api/login 免认证）
adminApp.use('/api/*', adminAuth)

// 统计概览
adminApp.get('/api/stats', async c => {
  try {
    const [totalUsers, totalCols, todayUsers, todayCols] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as c FROM users').first(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM collections').first(),
      c.env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE created_at >= date('now')").first(),
      c.env.DB.prepare("SELECT COUNT(*) as c FROM collections WHERE created_at >= date('now')").first(),
    ])
    return c.json({ success: true, data: {
      total_users: (totalUsers as any)?.c || 0,
      total_collections: (totalCols as any)?.c || 0,
      today_users: (todayUsers as any)?.c || 0,
      today_collections: (todayCols as any)?.c || 0,
    }})
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 用户列表（支持搜索）
adminApp.get('/api/users', async c => {
  try {
    const page = Math.max(1, parseInt(c.req.query('page') || '1'))
    const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') || '20')))
    const offset = (page - 1) * limit
    const status = c.req.query('status')
    const search = c.req.query('search')

    let where = 'WHERE 1=1'
    const binds: string[] = []
    if (status) { where += ' AND status = ?'; binds.push(status) }
    if (search) { where += ' AND phone LIKE ?'; binds.push(`%${search}%`) }

    const countRow = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM users ${where}`).bind(...binds).first()
    const total = (countRow as any)?.total || 0

    const rows = await c.env.DB.prepare(
      `SELECT id, phone, nickname, role, status, created_at, last_login_at FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(...binds, limit.toString(), offset.toString()).all()

    const results = []
    for (const u of (rows.results || [])) {
      const collCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM collections WHERE user_id = ?').bind((u as any).id).first()
      results.push({ ...(u as any), phone: maskPhone((u as any).phone), collection_count: (collCount as any)?.cnt || 0 })
    }
    return c.json({ success: true, data: results, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 切换用户状态
adminApp.patch('/api/users/:id/status', async c => {
  try {
    const { status } = await c.req.json()
    const payload = c.get('adminPayload')
    await c.env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(status, c.req.param('id')).run()
    await c.env.DB.prepare("INSERT INTO admin_logs (admin_id, action, ip, detail, created_at) VALUES (?, 'toggle_user', ?, ?, ?)")
      .bind(parseInt(payload.sub as string), c.req.header('CF-Connecting-IP')||'unknown', `设置用户#${c.req.param('id')}状态为${status}`, new Date().toISOString()).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 收藏列表
adminApp.get('/api/collections', async c => {
  try {
    const page = Math.max(1, parseInt(c.req.query('page') || '1'))
    const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') || '20')))
    const offset = (page - 1) * limit
    const search = c.req.query('search')

    let where = 'WHERE 1=1'
    const binds: string[] = []
    if (search) { where += ' AND (title LIKE ? OR url LIKE ?)'; binds.push(`%${search}%`, `%${search}%`) }

    const countRow = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM collections ${where}`).bind(...binds).first()
    const total = (countRow as any)?.total || 0

    const rows = await c.env.DB.prepare(
      `SELECT c.id, c.title, c.url, c.platform, c.created_at, u.phone as user_phone
       FROM collections c LEFT JOIN users u ON c.user_id = u.id
       ${where} ORDER BY c.created_at DESC LIMIT ? OFFSET ?`
    ).bind(...binds, limit.toString(), offset.toString()).all()

    return c.json({ success: true, data: rows.results || [], pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 删除收藏
adminApp.delete('/api/collections/:id', async c => {
  try {
    const payload = c.get('adminPayload')
    await c.env.DB.prepare('DELETE FROM collections WHERE id = ?').bind(c.req.param('id')).run()
    await c.env.DB.prepare("INSERT INTO admin_logs (admin_id, action, ip, detail, created_at) VALUES (?, 'delete_collection', ?, ?, ?)")
      .bind(parseInt(payload.sub as string), c.req.header('CF-Connecting-IP')||'unknown', `删除收藏#${c.req.param('id')}`, new Date().toISOString()).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 操作日志
adminApp.get('/api/logs', async c => {
  try {
    const page = Math.max(1, parseInt(c.req.query('page') || '1'))
    const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') || '20')))
    const offset = (page - 1) * limit
    const action = c.req.query('action')

    let where = 'WHERE 1=1'
    const binds: string[] = []
    if (action) { where += ' AND action = ?'; binds.push(action) }

    const countRow = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM admin_logs ${where}`).bind(...binds).first()
    const total = (countRow as any)?.total || 0

    const rows = await c.env.DB.prepare(
      `SELECT l.id, l.action, l.ip, l.detail, l.created_at, u.phone as admin_phone
       FROM admin_logs l LEFT JOIN users u ON l.admin_id = u.id
       ${where} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
    ).bind(...binds, limit.toString(), offset.toString()).all()

    return c.json({ success: true, data: rows.results || [], pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
  } catch (e: any) { return c.json({ success: false, error: e?.message }, 500) }
})

// 挂载管理后台
//   /admin              → HTML管理页面（无需认证）
//   /admin/api/login    → 登录API（无需认证）
//   /admin/api/*        → 需Admin JWT认证
app.route('/admin', adminApp)

// 健康检查
app.get('/health', c => c.json({ success: true, message: 'OK', timestamp: new Date().toISOString() }))

export default { fetch: app.fetch }
