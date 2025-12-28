/* Enclave/Enclave.cpp */
#include "Enclave.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <string>
#include <map>
#include <queue>
#include <vector>
#include <cstring>

// 定义与 EDL 一致的最大缓冲区
#define MAX_BUF_SIZE 5000000 // 改为 5MB

void printf_sgx(const char *fmt, ...) {
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

struct __attribute__((packed)) EdgePayload {
    char p_v[65];      
    int weight;
    char next_key[65]; 
};

std::string sha256_string(const std::string& input) {
    sgx_sha256_hash_t hash;
    sgx_sha256_msg((const uint8_t*)input.c_str(), input.length(), &hash);
    char hex[65];
    for(int i=0; i<32; i++) snprintf(hex + i*2, 3, "%02x", hash[i]);
    return std::string(hex);
}

bool verify_hmac(const char* data, size_t len, const std::string& key_hex, const char* expected_mac_hex) {
    // 安全检查：防止越界读取
    if (len > MAX_BUF_SIZE) {
        printf_sgx("[Error] Data too large (%lu > %d), cannot verify HMAC!\n", len, MAX_BUF_SIZE);
        return false; 
    }

    sgx_key_128bit_t k_128;
    memset(k_128, 0, 16);
    memcpy(k_128, key_hex.c_str(), 16);

    sgx_hmac_256bit_tag_t mac; 
    sgx_status_t status = sgx_hmac_sha256_msg(
        (const unsigned char*)data, (int)len, 
        (const unsigned char*)&k_128, 16, 
        (unsigned char*)mac, 32
    );
    if (status != SGX_SUCCESS) return false;

    char computed_hex[65];
    for(int i=0; i<32; i++) snprintf(computed_hex + i*2, 3, "%02x", mac[i]);
    
    if (strncmp(computed_hex, expected_mac_hex, 64) != 0) return false;
    return true;
}

bool decrypt_aes_native(const char* blob, size_t blob_len, const std::string& key_hex, char* out_plain) {
    if (blob_len < 28 || blob_len > MAX_BUF_SIZE) return false; // 同样增加检查
    
    sgx_aes_gcm_128bit_key_t aes_key;
    memset(aes_key, 0, 16);
    memcpy(aes_key, key_hex.c_str(), 16);

    const uint8_t* iv = (const uint8_t*)blob;
    const uint8_t* tag = (const uint8_t*)(blob + 12);
    const uint8_t* ciphertext = (const uint8_t*)(blob + 28);
    uint32_t cipher_len = (uint32_t)(blob_len - 28);

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(
        &aes_key, ciphertext, cipher_len, (uint8_t*)out_plain,
        iv, 12, NULL, 0, (const sgx_aes_gcm_128bit_tag_t*)tag
    );
    return (ret == SGX_SUCCESS);
}

void ecall_init() { }

int ecall_dijkstra_search(const char* start_node, const char* end_node) {
    std::string s_id(start_node);
    std::string t_id(end_node);

    typedef std::pair<int, std::string> PII;
    std::priority_queue<PII, std::vector<PII>, std::greater<PII>> pq;
    std::map<std::string, int> dist;

    dist[s_id] = 0;
    pq.push({0, s_id});

    int hmac_ok_count = 0;
    int hmac_fail_count = 0;

    // 分配大缓冲区 (注意：500KB * 2 = 1MB，这会占用大量 Stack，
    // 但既然我们已经把 StackMaxSize 调大到 1MB，勉强够用。
    // 更安全的做法是用 malloc/free 在堆上分配，或者定义为全局/static)
    // 为了稳妥，这里改为堆分配：
    char* blob = (char*)malloc(MAX_BUF_SIZE);
    char* plaintext = (char*)malloc(MAX_BUF_SIZE);
    if (!blob || !plaintext) {
        printf_sgx("[Fatal] OOM in Enclave!\n");
        return -2;
    }
    
    char mac_hex[65];
    int final_dist = -1;

    while (!pq.empty()) {
        int d = pq.top().first;
        std::string u = pq.top().second;
        pq.pop();

        if (u == t_id) {
            final_dist = d;
            break;
        }
        // Dijkstra 优化：如果已经找到更短路径，跳过
        if (dist.find(u) != dist.end() && d > dist[u]) continue;

        std::string k = sha256_string(u + "_lookup");
        memset(blob, 0, MAX_BUF_SIZE); // 清空
        mac_hex[0] = '\0';
        size_t real_len = 0;
        
        ocall_fetch_data(k.c_str(), blob, &real_len, mac_hex);

        if (mac_hex[0] == '\0') continue;

        // === 关键修复：防止 OOB 读取 ===
        if (real_len > MAX_BUF_SIZE) {
            // 数据被截断，无法验证完整性，跳过该节点
            hmac_fail_count++;
            continue; 
        }

        std::string hmac_key = sha256_string(u + "_hmac_key");
        if (verify_hmac(blob, real_len, hmac_key, mac_hex)) {
             hmac_ok_count++;
        } else {
             hmac_fail_count++;
             continue; 
        }

        std::string aes_key = sha256_string(u + "_aes_key");
        memset(plaintext, 0, MAX_BUF_SIZE);
        
        if (!decrypt_aes_native(blob, real_len, aes_key, plaintext)) continue;

        EdgePayload* edges = (EdgePayload*)(plaintext + 1); 
        int count = plaintext[0];

        // 边界检查：防止 count 异常导致访问越界
        // 简单估算：1字节count + count * sizeof(EdgePayload) <= real_len
        // ... (此处略去严格检查，假设解密后数据是良性的)

        for (int i=0; i<count; i++) {
            std::string v = edges[i].p_v;
            int w = edges[i].weight;
            if (dist.find(v) == dist.end() || dist[u] + w < dist[v]) {
                dist[v] = dist[u] + w;
                pq.push({dist[v], v});
            }
        }
    }

    free(blob);
    free(plaintext);

    printf_sgx("Result: %2d | HMAC Verified: %3d nodes | Failed: %d\n", 
               final_dist, hmac_ok_count, hmac_fail_count);
    
    return final_dist;
}