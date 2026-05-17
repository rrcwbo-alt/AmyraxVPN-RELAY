const HOP_BY_HOP_HEADERS = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate", 
  "proxy-authorization", "te", "trailer", "transfer-encoding", 
  "upgrade", "forwarded", "x-forwarded-host", "x-forwarded-proto", 
  "x-forwarded-port"
]);

const FALLBACK_HTML_URL = "https://amyraxvpn-main.github.io/AmyraxVPN-RELAY/";
const SAFE_METHODS = new Set(["GET", "HEAD"]);
const REAL_IP_HEADERS = ["x-real-ip", "x-forwarded-for"];
const STRIP_PREFIXES = ["x-nf-", "x-netlify-"];

export default async function handleRequest(request, context) {
  try {
    const urlObj = new URL(request.url);
    const pathname = urlObj.pathname;
    const search = urlObj.search;
    const targetHost = request.headers.get("x-host");

    // 1. Fallback for direct browser visits without configuration headers
    if (pathname === "/" && !targetHost) {
      const upgradeHeader = (request.headers.get("upgrade") || "").toLowerCase();
      if (upgradeHeader !== "websocket") {
        const staticPageResponse = await fetch(FALLBACK_HTML_URL);
        const htmlContent = await staticPageResponse.text();
        return new Response(htmlContent, {
          headers: { "content-type": "text/html; charset=UTF-8" },
        });
      }
    }

    // 2. Stop empty processing requests
    if (!targetHost) {
      return new Response("Error: x-host header is missing.", { status: 400 });
    }

    // 3. Resolve destination URL protocol
    let destinationUrl;
    if (targetHost.startsWith("http://") || targetHost.startsWith("https://")) {
      destinationUrl = targetHost + pathname + search;
    } else {
      const useHttps = !targetHost.includes(":") || targetHost.includes(":443") || /^s\d+\./.test(targetHost);
      destinationUrl = (useHttps ? "https://" : "http://") + targetHost + pathname + search;
    }

    // 4. Sanitize Headers
    const forwardedHeaders = new Headers();
    let clientIp = null;

    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(lowerKey) || STRIP_PREFIXES.some(p => lowerKey.startsWith(p)) || lowerKey === "x-host") {
        continue;
      }
      if (lowerKey === REAL_IP_HEADERS[0]) { clientIp = value; continue; }
      if (lowerKey === REAL_IP_HEADERS[1]) { if (!clientIp) clientIp = value; continue; }
      forwardedHeaders.set(lowerKey, value);
    }

    if (clientIp) {
      forwardedHeaders.set("x-forwarded-for", clientIp);
    }

    // 5. Stream Body Data
    const method = request.method;
    let requestBody = null;
    if (!SAFE_METHODS.has(method) && request.body) {
      requestBody = await request.arrayBuffer();
    }

    // 6. Upstream Forwarding
    const upstreamResponse = await fetch(destinationUrl, {
      method: method,
      headers: forwardedHeaders,
      redirect: "manual",
      body: requestBody,
    });

    // 7. Format Downstream Response
    const responseHeaders = new Headers();
    for (const [key, value] of upstreamResponse.headers) {
      if (key.toLowerCase() === "transfer-encoding") continue;
      responseHeaders.set(key, value);
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });

  } catch {
    return new Response("Bad Gateway: Relay Failed", { status: 502 });
  }
}
