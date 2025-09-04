# Frida-HTTP-logging
Frida script that logs (in real time) almost all HTTP(S) traffic from common Android stacks—OkHttp v3/v4 (via a universal Interceptor injection), plus a HttpURLConnection fallback. It prints method, URL, headers, and bodies when readable (UTF-8 / text). Drop it as-is into your Frida session
