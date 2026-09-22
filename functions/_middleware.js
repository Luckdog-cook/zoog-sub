/**
 * Cloudflare Pages Functions 中间件 —— 订阅鉴权
 *
 * 令牌保存在 Pages 环境变量 SUB_TOKEN 中(不写入代码库,避免公开仓库泄露)。
 * 通过方式二选一:
 *   1) 查询参数: https://plutox13117.dpdns.org/zoog.txt?token=xxxx
 *   2) 请求头:   X-Sub-Token: xxxx
 *
 * 未配置 SUB_TOKEN 时自动放行(防止误锁死)。
 */
export async function onRequest(context) {
  const { request, env } = context;
  const expected = env.SUB_TOKEN;

  if (!expected) {
    return context.next();
  }

  const url = new URL(request.url);
  const fromQuery = url.searchParams.get('token');
  const fromHeader = request.headers.get('x-sub-token');

  if (fromQuery === expected || fromHeader === expected) {
    return context.next();
  }

  return new Response('401 Unauthorized\n', {
    status: 401,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
