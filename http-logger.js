// frida -U -f <package> -l http-logger.js --no-pause
Java.perform(function () {
  function log(msg) { try { console.log(msg); } catch (_) {} }
  function safe(fn, label) { try { return fn(); } catch (e) { log("[!] " + label + ": " + e); return null; } }

  // ---- Helpers (Java types) ----
  var JString = Java.use('java.lang.String');
  var System = Java.use('java.lang.System');
  var Charset = Java.use('java.nio.charset.Charset');
  var StandardCharsets = Java.use('java.nio.charset.StandardCharsets');
  var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
  var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
  var Arrays = Java.use('java.util.Arrays');

  // okio helpers (used by OkHttp)
  var BufferCls = safe(() => Java.use('okio.Buffer'), 'okio.Buffer');
  var GzipSource = safe(() => Java.use('okio.GzipSource'), 'okio.GzipSource');
  var Okio = safe(() => Java.use('okio.Okio'), 'okio.Okio');

  // ---- 1) OKHTTP (v3 / v4): universal interceptor injection ----
  try {
    var Interceptor = Java.use('okhttp3.Interceptor');
    var Request = Java.use('okhttp3.Request');
    var Response = Java.use('okhttp3.Response');
    var MediaType = Java.use('okhttp3.MediaType');

    // A dynamic interceptor we’ll insert into every OkHttpClient.Builder
    var FridaInterceptor = Java.registerClass({
      name: 'com.frida.NetworkSniffer',
      implements: [Interceptor],
      methods: {
        intercept: function (chain) {
          var request = chain.request();
          var url = request.url().toString();
          var method = request.method();
          var reqHeaders = request.headers();

          // ---- request body (best-effort) ----
          var reqBodyStr = '';
          var reqBody = request.body();
          if (reqBody && BufferCls) {
            try {
              var buffer = BufferCls.$new();
              reqBody.writeTo(buffer);

              // If content-encoding is gzip (rare for requests), try to ungzip
              var ce = reqHeaders.get('Content-Encoding');
              if (ce && ce.toLowerCase().indexOf('gzip') !== -1 && Okio && GzipSource) {
                var gz = GzipSource.$new(buffer.clone());
                var out = BufferCls.$new();
                out.writeAll(gz);
                gz.close();
                reqBodyStr = out.readUtf8();
              } else {
                reqBodyStr = buffer.readUtf8();
              }
            } catch (e) {
              reqBodyStr = '<non-text or too large>';
            }
          }

          log([
            '┌── [OkHttp Request]',
            '│ ' + method + ' ' + url,
            '│ Headers:\n' + String(reqHeaders),
            reqBody ? ('│ Body:\n' + reqBodyStr) : '│ Body: <none>',
            '└────────────────────────────────────────'
          ].join('\n'));

          // Proceed and time it
          var start = System.nanoTime();
          var response = chain.proceed(request);
          var tookMs = (System.nanoTime() - start) / 1000000.0;

          // ---- response body (best-effort, preserving stream) ----
          var code = response.code();
          var message = response.message();
          var respHeaders = response.headers();
          var body = response.body();

          var respBodyStr = '';
          if (body && BufferCls) {
            try {
              var source = body.source();
              source.request(0x7fffffff); // Buffer the entire body
              var buffer2 = source.buffer().clone();

              // Ungzip if needed
              var rce = respHeaders.get('Content-Encoding');
              if (rce && rce.toLowerCase().indexOf('gzip') !== -1 && Okio && GzipSource) {
                var gz2 = GzipSource.$new(buffer2);
                var out2 = BufferCls.$new();
                out2.writeAll(gz2);
                gz2.close();
                respBodyStr = out2.readUtf8();
              } else {
                respBodyStr = buffer2.readUtf8();
              }
            } catch (e2) {
              respBodyStr = '<non-text or too large>';
            }
          }

          log([
            '┌── [OkHttp Response]',
            '│ ' + code + ' ' + message + '  (' + tookMs.toFixed(1) + ' ms)  ' + url,
            '│ Headers:\n' + String(respHeaders),
            body ? ('│ Body:\n' + respBodyStr) : '│ Body: <none>',
            '└────────────────────────────────────────'
          ].join('\n'));

          return response;
        }
      }
    });

    // Hook Builder.build() to inject our interceptor once per client
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');
    var buildOverload = Builder.build.overload();
    var addedFieldName = '__frida_added_interceptor';

    // Add a tiny flag on the Builder instance to avoid double-injecting
    Builder.build.implementation = function () {
      try {
        if (!this.hasOwnProperty(addedFieldName) || !this[addedFieldName]) {
          this.addInterceptor(FridaInterceptor.$new());
          this[addedFieldName] = true;
          log('[+] Injected Frida Interceptor into OkHttpClient.Builder');
        }
      } catch (e) {
        log('[!] Failed to add OkHttp interceptor: ' + e);
      }
      return buildOverload.call(this);
    };

    log('[*] OkHttp interceptor hook ready.');
  } catch (e) {
    log('[!] OkHttp hook setup failed (package okhttp3 missing?): ' + e);
  }

  // ---- 2) HttpURLConnection fallback (catches plain java.net.* clients, WebView, etc) ----
  try {
    var URL = Java.use('java.net.URL');
    var URLConnection = Java.use('java.net.URLConnection');
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');

    // Hook openConnection to capture target URLs
    URL.openConnection.overload().implementation = function () {
      var conn = this.openConnection.overload().call(this);
      try {
        var u = this.toString();
        // Mark connection with URL for later logs
        conn._frida_url = u;
      } catch (_) {}
      return conn;
    };

    // Track method and headers
    HttpURLConnection.setRequestMethod.implementation = function (m) {
      this.setRequestMethod.call(this, m);
      try { this._frida_method = m; } catch (_) {}
    };

    HttpURLConnection.setRequestProperty.implementation = function (k, v) {
      this.setRequestProperty.call(this, k, v);
      try {
        if (!this._frida_headers) this._frida_headers = {};
        this._frida_headers[k + ''] = v + '';
      } catch (_) {}
    };

    // Capture request body
    HttpURLConnection.getOutputStream.implementation = function () {
      var os = this.getOutputStream.call(this);
      try {
        var bos = Java.use('java.io.ByteArrayOutputStream').$new();
        var FilterOutputStream = Java.use('java.io.FilterOutputStream');
        var Wrapped = Java.registerClass({
          name: 'com.frida.ConnOutStream',
          superClass: FilterOutputStream,
          fields: {
            _bos: 'java.io.ByteArrayOutputStream'
          },
          methods: {
            write: [
              {
                returnType: 'void',
                argumentTypes: ['int'],
                implementation: function (b) {
                  this.$super.write.overload('int').call(this, b);
                  this._bos.write(b);
                }
              },
              {
                returnType: 'void',
                argumentTypes: ['[B'],
                implementation: function (ba) {
                  this.$super.write.overload('[B').call(this, ba);
                  this._bos.write(ba);
                }
              },
              {
                returnType: 'void',
                argumentTypes: ['[B', 'int', 'int'],
                implementation: function (ba, off, len) {
                  this.$super.write.overload('[B', 'int', 'int').call(this, ba, off, len);
                  this._bos.write(ba, off, len);
                }
              }
            ],
            close: {
              returnType: 'void',
              argumentTypes: [],
              implementation: function () {
                this.$super.close.call(this);
              }
            }
          }
        });

        var wrapped = Wrapped.$new(os);
        wrapped._bos.value = bos;
        this._frida_req_body = bos;
        return wrapped;
      } catch (e) {
        log('[!] getOutputStream wrap failed: ' + e);
        return os;
      }
    };

    // Log on connect / getInputStream (request is going out)
    var logOnce = function (conn, when) {
      try {
        var url = conn._frida_url || conn.getURL().toString();
        var method = conn._frida_method || conn.getRequestMethod();
        var hdrs = conn._frida_headers || {};
        var hdrStr = Object.keys(hdrs).map(k => k + ': ' + hdrs[k]).join('\n');

        var bodyStr = '';
        if (conn._frida_req_body) {
          bodyStr = JString.$new(conn._frida_req_body.toByteArray(), StandardCharsets.UTF_8.value).toString();
        }

        log([
          '┌── [HttpURLConnection ' + when + ']',
          '│ ' + method + ' ' + url,
          '│ Headers:\n' + (hdrStr || '<none>'),
          '│ Body:\n' + (bodyStr || '<none>'),
          '└────────────────────────────────────────'
        ].join('\n'));
      } catch (e) {
        log('[!] HttpURLConnection log failed: ' + e);
      }
    };

    HttpURLConnection.connect.implementation = function () {
      logOnce(this, 'connect()');
      return this.connect.call(this);
    };

    HttpURLConnection.getInputStream.implementation = function () {
      logOnce(this, 'getInputStream()');
      var is = this.getInputStream.call(this);
      // Also try to read and clone response (best effort)
      try {
        var baos = ByteArrayOutputStream.$new();
        var buf = Java.array('byte', new Array(4096).fill(0));
        var bis = Java.use('java.io.BufferedInputStream').$new(is);
        var read;
        while ((read = bis.read(buf)) > 0) {
          baos.write(buf, 0, read);
        }
        var data = baos.toByteArray();
        var copy = ByteArrayInputStream.$new(data);
        // Return a fresh stream to the app
        return copy;
      } catch (e) {
        // if anything goes wrong, just give original stream back
        return is;
      }
    };

    log('[*] HttpURLConnection fallback hook ready.');
  } catch (e) {
    log('[!] HttpURLConnection hook setup failed: ' + e);
  }

  log('[✓] Network logging is active.');
});
