/* mini-https.c
 * Minimal self-contained HTTPS server using libmicrohttpd + OpenSSL.
 *
 * 1. Checks for cert.pem/key.pem in current directory.
 * 2. If not present, automatically generates them.
 * 3. Listens on HTTPS (default port 8080).
 * 4. Logs requests to stdout.
 *
 * Compile (Arch Linux):
 *   cc https_server.c -o https_server -lmicrohttpd -lssl -lcrypto
 *
 * Run:
 *   ./https_server
 *
 * Access in a browser:
 *   https://<your-local-IP>:8080
 * Author: frankischilling
 */

#include <microhttpd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>           // for getnameinfo
#include <arpa/inet.h>       // for inet_ntop
#include <sys/socket.h>      // for AF_INET, AF_INET6
#include <netinet/in.h>      // for sockaddr_in
#include <sys/types.h>       // for getaddrinfo, etc.
#include <ifaddrs.h>         // for getifaddrs

#define PORT        8080
#define CERT_FILE   "cert.pem"
#define KEY_FILE    "key.pem"

#define MAX_MESSAGES 100
#define MAX_MESSAGE_LENGTH 512

// Message queue
char message_queue[MAX_MESSAGES][MAX_MESSAGE_LENGTH];
int message_count = 0;
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;

// HTML for the chat interface
const char *chat_page =
    "<!DOCTYPE html>"
    "<html>"
    "<head><title>Chat</title></head>"
    "<body>"
    "<h1>Chat Room</h1>"
    "<div id='messages' style='height: 300px; overflow-y: scroll; border: 1px solid black;'></div>"
    "<form id='chatForm'>"
    "  <input type='text' id='message' placeholder='Type your message...' required />"
    "  <button type='submit'>Send</button>"
    "</form>"
    "<script>"
    "async function fetchMessages() {"
    "  const response = await fetch('/messages');"
    "  const messages = await response.text();"
    "  document.getElementById('messages').innerHTML = messages;"
    "}"
    "setInterval(fetchMessages, 1000);"
    "document.getElementById('chatForm').addEventListener('submit', async (e) => {"
    "  e.preventDefault();"
    "  const message = document.getElementById('message').value;"
    "  await fetch('/', { method: 'POST', body: message });"
    "  document.getElementById('message').value = '';"
    "});"
    "</script>"
    "</body>"
    "</html>";

// Read an entire file into memory (caller must free the returned buffer)
static char* read_file(const char *filename, long *out_size)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("[ERROR] fopen");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = (char*)malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        perror("[ERROR] malloc");
        return NULL;
    }

    if (fread(buffer, 1, size, fp) != (size_t)size) {
        perror("[ERROR] fread");
        fclose(fp);
        free(buffer);
        return NULL;
    }
    fclose(fp);

    buffer[size] = '\0'; // Null-terminate
    if (out_size) *out_size = size;
    return buffer;
}

// Generate a self-signed certificate using OpenSSL command line
static void generate_certificates(void)
{
    printf("[INFO] Generating self-signed certificate...\n");
    int ret = system(
        "openssl req -newkey rsa:2048 -nodes -x509 -sha256 -days 365 "
        "-subj \"/CN=localhost\" "
        "-keyout " KEY_FILE " -out " CERT_FILE
    );
    if (ret != 0) {
        fprintf(stderr, "[ERROR] Failed to generate certificate (openssl ret=%d)\n", ret);
    }
}

// We'll define a small struct to hold the partial POST data between calls.
struct PostData
{
    char buffer[MAX_MESSAGE_LENGTH];
    size_t offset; // how much data we've written so far
};

// Handle POST requests (add a message to the queue) with chunked support
static enum MHD_Result handle_post_request(
    struct MHD_Connection *connection,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    // If this is the first call for this connection, allocate a PostData struct.
    if (*con_cls == NULL) {
        struct PostData *pd = calloc(1, sizeof(struct PostData));
        if (!pd)
            return MHD_NO;  // Allocation failure, cannot proceed
        *con_cls = pd;
        return MHD_YES;
    }

    struct PostData *pd = (struct PostData *)(*con_cls);

    // If we still have data left, copy it into our buffer
    if (*upload_data_size > 0)
    {
        size_t copy_size = *upload_data_size;
        // Ensure we don't overflow pd->buffer
        if (pd->offset + copy_size >= MAX_MESSAGE_LENGTH)
            copy_size = MAX_MESSAGE_LENGTH - pd->offset - 1;

        memcpy(pd->buffer + pd->offset, upload_data, copy_size);
        pd->offset += copy_size;
        pd->buffer[pd->offset] = '\0'; // Null-terminate

        // Mark data as processed
        *upload_data_size = 0;
        return MHD_YES;
    }
    else
    {
        // *upload_data_size == 0 => we have received all POST data
        // Now we can safely process the full data in pd->buffer

        // Retrieve the client IP from the connection info
        const union MHD_ConnectionInfo *conn_info =
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);

        char client_ip[NI_MAXHOST] = "unknown";
        if (conn_info && conn_info->client_addr) {
            getnameinfo(conn_info->client_addr,
                        (conn_info->client_addr->sa_family == AF_INET)
                            ? sizeof(struct sockaddr_in)
                            : sizeof(struct sockaddr_in6),
                        client_ip, sizeof(client_ip),
                        NULL, 0, NI_NUMERICHOST);
        }

        pthread_mutex_lock(&message_mutex);

        if (message_count < MAX_MESSAGES) {
            snprintf(message_queue[message_count],
                     MAX_MESSAGE_LENGTH,
                     "[%s] %s", client_ip, pd->buffer); // prepend IP to the message
            message_count++;
            printf("[INFO] Message added from %s: %s\n", client_ip, pd->buffer);
        } else {
            printf("[WARN] Message queue full. Discarding message from %s: %s\n",
                   client_ip, pd->buffer);
        }

        pthread_mutex_unlock(&message_mutex);

        // Now we must send a response to the client:
        const char *response_text = "Message received";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(response_text),
            (void *)response_text,
            MHD_RESPMEM_PERSISTENT
        );
        if (!response) {
            free(pd);
            return MHD_NO;
        }

        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        // Clean up the memory we allocated for this connection
        free(pd);
        *con_cls = NULL; // Avoid double-free in future calls

        return ret;
    }
}

// Handle GET requests for messages
static enum MHD_Result handle_get_messages(struct MHD_Connection *connection)
{
    pthread_mutex_lock(&message_mutex);

    char response_buffer[MAX_MESSAGES * MAX_MESSAGE_LENGTH] = {0};
    for (int i = 0; i < message_count; i++) {
        strcat(response_buffer, message_queue[i]);
        strcat(response_buffer, "<br>"); // HTML break for readability
    }

    pthread_mutex_unlock(&message_mutex);

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_buffer),
                                                                    (void *)response_buffer,
                                                                    MHD_RESPMEM_MUST_COPY);
    if (!response)
        return MHD_NO;

    MHD_add_response_header(response, "Content-Type", "text/html");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

// Handle GET requests for the chat page
static enum MHD_Result handle_get_page(struct MHD_Connection *connection)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(chat_page),
                                                                    (void *)chat_page,
                                                                    MHD_RESPMEM_PERSISTENT);
    if (!response)
        return MHD_NO;

    MHD_add_response_header(response, "Content-Type", "text/html");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

// Request handler
static enum MHD_Result ahc_echo(void *cls,
                                struct MHD_Connection *connection,
                                const char *url,
                                const char *method,
                                const char *version,
                                const char *upload_data,
                                size_t *upload_data_size,
                                void **con_cls)
{
    printf("[LOG] %s request for %s\n", method, url);

    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/messages") == 0) {
            return handle_get_messages(connection);
        } else {
            return handle_get_page(connection);
        }
    } else if (strcmp(method, "POST") == 0) {
        return handle_post_request(connection, upload_data, upload_data_size, con_cls);
    }

    return MHD_NO; // Unsupported method
}

int main(int argc, char *argv[])
{
    // Print the server hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("[INFO] Server Hostname: %s\n", hostname);
    } else {
        perror("[WARN] gethostname");
    }

    // Retrieve and print the local IP address
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = "127.0.0.1"; // Default to localhost if no IP found

    if (getifaddrs(&ifaddr) == -1) {
        perror("[ERROR] getifaddrs");
    } else {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;

            if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                break; // Use the first non-loopback IPv4 address
            }
        }
        freeifaddrs(ifaddr);
    }

    // Check if cert/key already exist; if not, generate them
    struct stat st_cert, st_key;
    if ((stat(CERT_FILE, &st_cert) != 0) || (stat(KEY_FILE, &st_key) != 0)) {
        generate_certificates();
    }

    // Read cert/key into memory
    long cert_size = 0, key_size = 0;
    char *cert_pem = read_file(CERT_FILE, &cert_size);
    char *key_pem  = read_file(KEY_FILE,  &key_size);

    if (!cert_pem || !key_pem) {
        fprintf(stderr, "[ERROR] Could not load certificate or key.\n");
        free(cert_pem);
        free(key_pem);
        return 1;
    }

    // Start the HTTPS server
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SSL | MHD_USE_INTERNAL_POLLING_THREAD,
        PORT,
        NULL,
        NULL,
        &ahc_echo,
        NULL,
        MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
        MHD_OPTION_HTTPS_MEM_KEY,  key_pem,
        MHD_OPTION_END
    );

    if (!daemon) {
        fprintf(stderr, "[ERROR] Failed to start HTTPS server.\n");
        free(cert_pem);
        free(key_pem);
        return 1;
    }

    printf("[INFO] HTTPS server started on port %d.\n", PORT);
    printf("[INFO] Access the chat at: https://%s:%d\n", ip, PORT);
    printf("[INFO] Press Ctrl+C to stop.\n");

    // Keep running until killed
    pause();

    // Cleanup
    MHD_stop_daemon(daemon);
    free(cert_pem);
    free(key_pem);

    return 0;
}

