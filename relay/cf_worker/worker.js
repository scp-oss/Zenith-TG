/**
 * cf_worker/worker.js -- прозрачный TCP-туннель через Cloudflare Worker,
 * ТОЛЬКО к официальным подсетям Telegram.
 *
 * Зачем: 149.154.167.99 (web.telegram.org) заблокирован на границе сети
 * NETH-4 на уровне null-route (SYN роняется целиком, подтверждено живым
 * тестом -- ни один --lua-desync= трюк zapret2 не помогает, манглить
 * нечего, пакет никуда не доходит). У Cloudflare Worker собственная
 * сеть, свой исходящий IP -- если у Cloudflare с Telegram чистая
 * связность (весьма вероятно), Worker сам открывает РЕАЛЬНЫЙ TCP до
 * настоящего IP Telegram и просто дырка в проводе между клиентом (по
 * WebSocket, через обычный Cloudflare edge -- не заблокирован) и этим
 * TCP-сокетом. НЕ рерайт контента (в отличие от обычного
 * reverse-proxy) -- TLS идёт end-to-end клиент<->настоящий Telegram,
 * поэтому абсолютные ссылки/CORS/service worker внутри самого
 * web.telegram.org не ломаются, они и не подозревают о существовании
 * тоннеля. Та же идея, что relay/transparent_relay.py, просто точка
 * "открыть соединение к настоящему IP" переехала на сеть Cloudflare.
 *
 * НАМЕРЕННО не открытый релей: (1) dst разрешён ТОЛЬКО из официальных
 * подсетей Telegram (см. ALLOWED_CIDRS, тот же список, что
 * cidr/telegram_ipv4.txt), любой другой dst -- отказ; (2) обязателен
 * секрет (переменная окружения RELAY_SECRET в настройках Worker,
 * задаётся вручную при деплое) -- без него 403, чтобы этим не мог
 * пользоваться кто угодно, кто угадает URL воркера.
 */
import { connect } from 'cloudflare:sockets';

// Официальные подсети Telegram (см. https://core.telegram.org/resources/cidr.txt,
// тот же список, что z2r_autobench/Zenith-TG/cidr/telegram_ipv4.txt --
// ОБНОВЛЯТЬ ВРУЧНУЮ ВМЕСТЕ С ТЕМ ФАЙЛОМ, если список у Telegram изменится).
const ALLOWED_CIDRS = [
  '91.105.192.0/23',
  '91.108.4.0/22',
  '91.108.8.0/22',
  '91.108.12.0/22',
  '91.108.16.0/22',
  '91.108.20.0/22',
  '91.108.56.0/22',
  '149.154.160.0/20',
  '185.76.151.0/24',
];

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function isAllowedDst(ip) {
  return ALLOWED_CIDRS.some((cidr) => ipInCidr(ip, cidr));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const dst = url.searchParams.get('dst') || '';
    const port = parseInt(url.searchParams.get('port') || '443', 10);
    const secret = url.searchParams.get('secret') || '';

    if (!env.RELAY_SECRET || secret !== env.RELAY_SECRET) {
      return new Response('forbidden', { status: 403 });
    }
    if (!isAllowedDst(dst)) {
      return new Response('dst not in allowed Telegram ranges', { status: 400 });
    }
    if (!(port > 0 && port < 65536)) {
      return new Response('bad port', { status: 400 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('expected websocket', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    let socket;
    try {
      socket = connect({ hostname: dst, port });
    } catch (e) {
      server.close(1011, 'connect failed');
      return new Response(null, { status: 101, webSocket: client });
    }

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    server.addEventListener('message', (event) => {
      const data = typeof event.data === 'string'
        ? new TextEncoder().encode(event.data)
        : new Uint8Array(event.data);
      writer.write(data).catch(() => {
        try { server.close(); } catch (_) {}
      });
    });
    server.addEventListener('close', () => {
      writer.close().catch(() => {});
    });
    server.addEventListener('error', () => {
      writer.close().catch(() => {});
    });

    (async () => {
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          server.send(value);
        }
      } catch (e) {
        // соединение к Telegram оборвалось -- закрываем клиентскую сторону
      } finally {
        try { server.close(); } catch (_) {}
      }
    })();

    return new Response(null, { status: 101, webSocket: client });
  },
};
