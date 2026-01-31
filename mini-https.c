/* mini-https-chat.c
 * Minimal self-contained HTTPS chat server using libmicrohttpd.
 *
 * Features:
 *  - Auto-generates cert.pem/key.pem (with SAN) if missing
 *  - HTTPS server (default port 8080)
 *  - Simple in-memory chat ring buffer
 *  - Safer message rendering (no innerHTML XSS)
 *  - Frees per-connection POST buffers even on abort
 *
 * Build (recommended on Arch):
 *   cc mini-https-chat.c -o mini-https-chat $(pkg-config --cflags --libs
 * libmicrohttpd) -lpthread
 *
 * Run:
 *   ./mini-https-chat
 *
 * Visit:
 *   https://127.0.0.1:8080
 *
 * Author: frankischilling (upgraded)
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <microhttpd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST 1
#endif

#define PORT 8080
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"

#define MAX_MESSAGES 200
#define MAX_MESSAGE_LENGTH 512

// ----------- Chat storage (ring buffer) -----------

typedef struct {
  time_t ts;
  char ip[NI_MAXHOST];
  char msg[MAX_MESSAGE_LENGTH];
} ChatMessage;

static ChatMessage g_msgs[MAX_MESSAGES];
static size_t g_head = 0;  // index of oldest
static size_t g_count = 0; // number of valid messages
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void strip_newlines(char *s) {
  for (; *s; s++) {
    if (*s == '\r' || *s == '\n')
      *s = ' ';
  }
}

// Adds message to ring buffer; overwrites oldest if full.
static void chat_push(const char *ip, const char *msg) {
  pthread_mutex_lock(&g_lock);

  size_t idx;
  if (g_count < MAX_MESSAGES) {
    idx = (g_head + g_count) % MAX_MESSAGES;
    g_count++;
  } else {
    // overwrite oldest
    idx = g_head;
    g_head = (g_head + 1) % MAX_MESSAGES;
  }

  g_msgs[idx].ts = time(NULL);
  snprintf(g_msgs[idx].ip, sizeof(g_msgs[idx].ip), "%s", ip ? ip : "unknown");
  snprintf(g_msgs[idx].msg, sizeof(g_msgs[idx].msg), "%s", msg ? msg : "");
  strip_newlines(g_msgs[idx].msg);

  pthread_mutex_unlock(&g_lock);
}

static void fmt_time(time_t t, char *out, size_t out_sz) {
  struct tm tmv;
  localtime_r(&t, &tmv);
  strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", &tmv);
}

// Builds messages as text/plain lines: "[time] [ip] message\n"
static char *chat_build_plain(size_t *out_len) {
  pthread_mutex_lock(&g_lock);

  // Worst-case estimate: each line ~ (32 + ip + msg + 4) bytes
  size_t cap = g_count * (64 + NI_MAXHOST + MAX_MESSAGE_LENGTH) + 32;
  if (cap < 256)
    cap = 256;

  char *buf = (char *)malloc(cap);
  if (!buf) {
    pthread_mutex_unlock(&g_lock);
    return NULL;
  }
  buf[0] = '\0';

  size_t used = 0;
  for (size_t i = 0; i < g_count; i++) {
    size_t idx = (g_head + i) % MAX_MESSAGES;

    char tbuf[32];
    fmt_time(g_msgs[idx].ts, tbuf, sizeof(tbuf));

    char line[1024];
    int n = snprintf(line, sizeof(line), "[%s] [%s] %s\n", tbuf, g_msgs[idx].ip,
                     g_msgs[idx].msg);
    if (n < 0)
      continue;

    size_t need = (size_t)n;

    if (used + need + 1 > cap) {
      // grow
      size_t new_cap = cap * 2;
      while (new_cap < used + need + 1)
        new_cap *= 2;
      char *nb = (char *)realloc(buf, new_cap);
      if (!nb) {
        free(buf);
        pthread_mutex_unlock(&g_lock);
        return NULL;
      }
      buf = nb;
      cap = new_cap;
    }

    memcpy(buf + used, line, need);
    used += need;
    buf[used] = '\0';
  }

  pthread_mutex_unlock(&g_lock);

  if (out_len)
    *out_len = used;
  return buf;
}

// ----------- Helpers -----------

static void log_msg(const char *fmt, ...) {
  char tbuf[32];
  time_t now = time(NULL);
  fmt_time(now, tbuf, sizeof(tbuf));
  fprintf(stdout, "[%s] ", tbuf);

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);

  fputc('\n', stdout);
  fflush(stdout);
}

static int file_exists(const char *path) { return access(path, R_OK) == 0; }

static char *read_file(const char *filename, long *out_size) {
  FILE *fp = fopen(filename, "rb");
  if (!fp)
    return NULL;

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  long size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }

  char *buffer = (char *)malloc((size_t)size + 1);
  if (!buffer) {
    fclose(fp);
    return NULL;
  }

  size_t got = fread(buffer, 1, (size_t)size, fp);
  fclose(fp);

  if (got != (size_t)size) {
    free(buffer);
    return NULL;
  }
  buffer[size] = '\0';
  if (out_size)
    *out_size = size;
  return buffer;
}

// Generate self-signed cert with SAN (works better in modern browsers)
static void generate_certificates(void) {
  log_msg("Generating self-signed certificate (%s/%s)...", CERT_FILE, KEY_FILE);

  // Tighten key permissions on create.
  mode_t old_umask = umask(0077);

  // SAN is important. Most modern browsers ignore CN-only certs.
  // OpenSSL >= 1.1.1 supports -addext.
  const char *cmd =
      "openssl req -newkey rsa:2048 -nodes -x509 -sha256 -days 365 "
      "-subj \"/CN=localhost\" "
      "-addext \"subjectAltName=DNS:localhost,IP:127.0.0.1\" "
      "-keyout " KEY_FILE " -out " CERT_FILE " >/dev/null 2>&1";

  int ret = system(cmd);
  umask(old_umask);

  if (ret != 0) {
    log_msg("ERROR: openssl failed (ret=%d). Install openssl or generate certs "
            "manually.",
            ret);
  } else {
    // Ensure key perms remain tight
    chmod(KEY_FILE, 0600);
    chmod(CERT_FILE, 0644);
    log_msg("Certificate generated.");
  }
}

static void get_client_ip(struct MHD_Connection *connection, char *out,
                          size_t out_sz) {
  snprintf(out, out_sz, "unknown");
  const union MHD_ConnectionInfo *ci =
      MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

  if (!ci || !ci->client_addr)
    return;

  int flags = NI_NUMERICHOST;
  socklen_t slen = 0;
  if (ci->client_addr->sa_family == AF_INET)
    slen = sizeof(struct sockaddr_in);
  else if (ci->client_addr->sa_family == AF_INET6)
    slen = sizeof(struct sockaddr_in6);
  else
    return;

  getnameinfo(ci->client_addr, slen, out, out_sz, NULL, 0, flags);
}

static void add_common_headers(struct MHD_Response *resp,
                               const char *content_type) {
  if (content_type)
    MHD_add_response_header(resp, "Content-Type", content_type);

  // basic hardening / behavior
  MHD_add_response_header(resp, "Cache-Control", "no-store");
  MHD_add_response_header(resp, "X-Content-Type-Options", "nosniff");
}

// ----------- HTTP UI -----------

static const char *chat_page =
    "<!doctype html>"
    "<html><head>"
    "  <meta charset='utf-8'/>"
    "  <meta name='viewport' content='width=device-width,initial-scale=1'/>"
    "  <title>Mini HTTPS Chat</title>"
    "  <style>"
    "    body{font-family:system-ui,Segoe "
    "UI,Roboto,Arial,sans-serif;margin:20px;}"
    "    #wrap{max-width:800px;margin:0 auto;}"
    "    #messages{height:360px;overflow:auto;border:1px solid "
    "#333;padding:10px;white-space:pre-wrap;background:#fafafa;}"
    "    form{margin-top:10px;display:flex;gap:8px;}"
    "    input{flex:1;padding:10px;font-size:16px;}"
    "    button{padding:10px 14px;font-size:16px;cursor:pointer;}"
    "    #status{margin-top:8px;font-size:13px;color:#b00020;min-height:1.2em;}"
    "    .hint{color:#555;margin-top:8px;font-size:13px;}"
    "  </style>"
    "</head><body>"
    "<div id='wrap'>"
    "  <h1>Mini HTTPS Chat</h1>"
    "  <div id='messages'></div>"
    "  <form id='chatForm'>"
    "    <input id='message' autocomplete='off' maxlength='480' "
    "placeholder='Type a message…' required />"
    "    <button type='submit'>Send</button>"
    "  </form>"
    "  <div id='status'></div>"
    "  <div class='hint'>If sending fails, the error will appear above.</div>"
    "</div>"
    "<script>"
    "  const box = document.getElementById('messages');"
    "  const input = document.getElementById('message');"
    "  const statusEl = document.getElementById('status');"
    "  let lastText = '';"
    "  function setStatus(s){ statusEl.textContent = s || ''; }"
    "  function renderText(t){"
    "    const nearBottom = (box.scrollTop + box.clientHeight) >= "
    "(box.scrollHeight - 40);"
    "    box.textContent = t;"
    "    if(nearBottom) box.scrollTop = box.scrollHeight;"
    "  }"
    "  async function fetchMessages(){"
    "    try{"
    "      const r = await fetch(window.location.origin + '/messages', "
    "{cache:'no-store'});"
    "      if(!r.ok) throw new Error('GET /messages HTTP ' + r.status);"
    "      const t = await r.text();"
    "      if(t !== lastText){ lastText = t; renderText(t); }"
    "    }catch(e){"
    "      console.error('fetchMessages failed:', e);"
    "      setStatus(String(e));"
    "    }"
    "  }"
    "  setInterval(fetchMessages, 800);"
    "  fetchMessages();"
    "  document.getElementById('chatForm').addEventListener('submit', async "
    "(e)=>{"
    "    e.preventDefault();"
    "    setStatus('');"
    "    const msg = input.value.trim();"
    "    if(!msg) return;"
    "    input.value='';"
    "    try{"
    "      const r = await fetch(window.location.origin + '/send', {"
    "        method:'POST',"
    "        headers:{'Content-Type':'text/plain;charset=utf-8'},"
    "        body: msg"
    "      });"
    "      if(!r.ok) throw new Error('POST /send HTTP ' + r.status);"
    "      fetchMessages();"
    "    }catch(e){"
    "      console.error('send failed:', e);"
    "      setStatus(String(e));"
    "    }"
    "  });"
    "</script>"
    "</body></html>";

// ----------- POST handling -----------

typedef struct {
  char buf[MAX_MESSAGE_LENGTH];
  size_t off;
  int done;
} PostData;

static enum MHD_Result respond_text(struct MHD_Connection *connection,
                                    unsigned code, const char *text,
                                    const char *content_type) {
  size_t len = text ? strlen(text) : 0;
  struct MHD_Response *resp =
      MHD_create_response_from_buffer(len, (void *)text, MHD_RESPMEM_MUST_COPY);
  if (!resp)
    return MHD_NO;
  add_common_headers(resp, content_type);
  enum MHD_Result r = MHD_queue_response(connection, code, resp);
  MHD_destroy_response(resp);
  return r;
}

static enum MHD_Result respond_buf(struct MHD_Connection *connection,
                                   unsigned code, char *buf, size_t len,
                                   const char *content_type) {
  struct MHD_Response *resp =
      MHD_create_response_from_buffer(len, (void *)buf, MHD_RESPMEM_MUST_FREE);
  if (!resp) {
    free(buf);
    return MHD_NO;
  }
  add_common_headers(resp, content_type);
  enum MHD_Result r = MHD_queue_response(connection, code, resp);
  MHD_destroy_response(resp);
  return r;
}

static enum MHD_Result handle_post_send(struct MHD_Connection *connection,
                                        const char *upload_data,
                                        size_t *upload_data_size,
                                        void **con_cls) {
  PostData *pd = (PostData *)(*con_cls);

  if (!pd) {
    pd = (PostData *)calloc(1, sizeof(PostData));
    if (!pd)
      return MHD_NO;
    *con_cls = pd;
    log_msg("POST init: %s", "alloc PostData");
    return MHD_YES;
  }

  if (*upload_data_size > 0) {
    log_msg("POST chunk: %zu bytes", *upload_data_size);
    size_t n = *upload_data_size;
    if (pd->off + n >= MAX_MESSAGE_LENGTH)
      n = (MAX_MESSAGE_LENGTH - 1) - pd->off;

    if (n > 0) {
      memcpy(pd->buf + pd->off, upload_data, n);
      pd->off += n;
      pd->buf[pd->off] = '\0';
    }

    *upload_data_size = 0;
    return MHD_YES;
  }

  // done receiving body
  if (!pd->done) {
    pd->done = 1;

    // trim leading/trailing spaces a bit
    char *s = pd->buf;
    while (*s == ' ' || *s == '\t')
      s++;

    // if empty message, just ok
    if (*s) {
      char ip[NI_MAXHOST];
      get_client_ip(connection, ip, sizeof(ip));
      chat_push(ip, s);
      log_msg("Message from %s: %s", ip, s);
    }
  }

  return respond_text(connection, MHD_HTTP_OK, "ok\n",
                      "text/plain; charset=utf-8");
}

// Called when request completes (also on abort). Frees per-connection state.
static void request_completed_cb(void *cls, struct MHD_Connection *connection,
                                 void **con_cls,
                                 enum MHD_RequestTerminationCode toe) {
  (void)cls;
  (void)connection;
  (void)toe;
  if (con_cls && *con_cls) {
    free(*con_cls);
    *con_cls = NULL;
  }
}

// ----------- Router -----------

static enum MHD_Result handler(void *cls, struct MHD_Connection *connection,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls) {
  (void)cls;
  (void)version;

  // Basic request log (less spammy than logging every poll chunk)
  if (*upload_data_size == 0)
    log_msg("%s %s", method, url);

  if (strcmp(method, "GET") == 0) {
    if (strcmp(url, "/messages") == 0) {
      size_t len = 0;
      char *buf = chat_build_plain(&len);
      if (!buf)
        return respond_text(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom\n",
                            "text/plain; charset=utf-8");
      return respond_buf(connection, MHD_HTTP_OK, buf, len,
                         "text/plain; charset=utf-8");
    }

    // default page
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(chat_page), (void *)chat_page, MHD_RESPMEM_PERSISTENT);
    if (!resp)
      return MHD_NO;
    add_common_headers(resp, "text/html; charset=utf-8");
    enum MHD_Result r = MHD_queue_response(connection, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return r;
  }

  if (strcmp(method, "POST") == 0) {
    if (strcmp(url, "/send") == 0 || strcmp(url, "/") == 0) {
      return handle_post_send(connection, upload_data, upload_data_size,
                              con_cls);
    }
    return respond_text(connection, MHD_HTTP_NOT_FOUND, "not found\n",
                        "text/plain; charset=utf-8");
  }

  return respond_text(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                      "method not allowed\n", "text/plain; charset=utf-8");
}

// ----------- main / shutdown -----------

static volatile sig_atomic_t g_run = 1;

static void on_sigint(int sig) {
  (void)sig;
  g_run = 0;
}

static void get_first_non_loopback_ipv4(char out[INET_ADDRSTRLEN]) {
  snprintf(out, INET_ADDRSTRLEN, "127.0.0.1");

  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) != 0)
    return;

  for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr)
      continue;
    if (ifa->ifa_addr->sa_family != AF_INET)
      continue;
    if (strcmp(ifa->ifa_name, "lo") == 0)
      continue;

    struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
    inet_ntop(AF_INET, &sa->sin_addr, out, INET_ADDRSTRLEN);
    break;
  }

  freeifaddrs(ifaddr);
}

int main(void) {
  signal(SIGINT, on_sigint);
  signal(SIGTERM, on_sigint);

  char hostname[256] = {0};
  if (gethostname(hostname, sizeof(hostname) - 1) != 0)
    snprintf(hostname, sizeof(hostname), "unknown");

  char ip[INET_ADDRSTRLEN];
  get_first_non_loopback_ipv4(ip);

  if (!file_exists(CERT_FILE) || !file_exists(KEY_FILE)) {
    generate_certificates();
  }

  long cert_size = 0, key_size = 0;
  char *cert_pem = read_file(CERT_FILE, &cert_size);
  char *key_pem = read_file(KEY_FILE, &key_size);

  if (!cert_pem || !key_pem) {
    fprintf(stderr, "ERROR: could not load %s/%s\n", CERT_FILE, KEY_FILE);
    free(cert_pem);
    free(key_pem);
    return 1;
  }

  // Seed chat with a startup line (optional)
  chat_push("server", "chat started");

  struct MHD_Daemon *d = MHD_start_daemon(
      MHD_USE_SSL | MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL, &handler,
      NULL, MHD_OPTION_HTTPS_MEM_CERT, cert_pem, MHD_OPTION_HTTPS_MEM_KEY,
      key_pem, MHD_OPTION_NOTIFY_COMPLETED, request_completed_cb, NULL,
      MHD_OPTION_END);

  if (!d) {
    fprintf(stderr, "ERROR: failed to start daemon\n");
    free(cert_pem);
    free(key_pem);
    return 1;
  }

  log_msg("Host: %s", hostname);
  log_msg("Listening: https://%s:%d", ip, PORT);
  log_msg("Also:      https://127.0.0.1:%d", PORT);
  log_msg("Ctrl+C to stop.");

  while (g_run) {
    sleep(1);
  }

  log_msg("Shutting down...");
  MHD_stop_daemon(d);
  free(cert_pem);
  free(key_pem);
  return 0;
}
