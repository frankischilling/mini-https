# mini_https

A **minimal self-contained HTTPS server** written in C using **libmicrohttpd** and **OpenSSL**.  
It automatically generates a self-signed certificate (if none exists) and serves a **simple chat interface** on HTTPS.

---

## Features

1. **Automatic Self-Signed Certificate**  
   - On first run, it checks for `cert.pem` and `key.pem` in the current directory.  
   - If missing, it calls OpenSSL to generate a self-signed certificate.

2. **Minimal Chat Interface**  
   - Clients can access the chat by visiting `https://<your-IP>:8080`.  
   - Messages posted are broadcast to all clients automatically (polled every second).

3. **Lightweight & Self-Contained**  
   - Uses `libmicrohttpd` for handling HTTPS requests/responses.  
   - Everything in a single C file for ease of portability.

4. **Local IP Detection**  
   - Scans network interfaces to display the primary non-loopback IPv4 address when the server starts.

5. **Basic Logging**  
   - Logs server startup details and all inbound requests.  
   - Logs chat messages along with the sender’s IP address.

---

## Getting Started

### 1. Install Dependencies

On **Arch Linux** (or similar), install the following:
```bash
sudo pacman -S libmicrohttpd openssl
```
*(Adjust for your distribution if needed.)*

### 2. Clone and Build

```bash
git clone https://github.com/<your-username>/mini_https.git
cd mini_https
cc mini_https.c -o mini_https -lmicrohttpd -lssl -lcrypto
```

### 3. Run

```bash
./mini_https
```
- On first run, this will generate `cert.pem` and `key.pem` in your current directory if they don't already exist.

### 4. Access the Chat

1. Check the console output for something like:
   ```
   [INFO] HTTPS server started on port 8080.
   [INFO] Access the chat at: https://10.0.56.245:8080
   ```
2. Open your browser to the indicated URL (e.g. `https://10.0.56.245:8080`).  
3. Accept the warning about a self-signed certificate.  
4. Start chatting with anyone else on the same local network!

---

## Example Output

```text
[INFO] Server Hostname: arch
[INFO] Available network interfaces:
  Interface: lo, IPv4 Address: 127.0.0.1
  Interface: wlan0, IPv4 Address: 10.0.56.245
  ...
[INFO] HTTPS server started on port 8080.
[INFO] Access the chat at: https://10.0.56.245:8080
[INFO] Press Ctrl+C to stop.
[LOG] GET request for /
[LOG] POST request for /
[INFO] Message added from 10.0.56.245: Hello World!
...
```

---

## Customization

- **Port**: Change `#define PORT 8080` to any other port (e.g., 443 if you have the necessary privileges).  
- **Certificate Details**: Update the `-subj` string in `generate_certificates()` if you want something other than `/CN=localhost`.  
- **Threading and Scaling**: `libmicrohttpd` can support thread pools or external poll loops for higher performance. This example uses an internal polling thread for simplicity.

---

---

## Roadmap

- **Custom config**: Allow users to change port, max clients, etc

---

## License

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

---

**Author**: @frankischilling  
Feel free to open issues, submit PRs, or fork for further enhancements!
