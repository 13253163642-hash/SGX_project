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

// [修改] 增大缓冲区到 20MB，以容纳超级节点
#define MAX_BUF_SIZE 20000000 

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
    if (len > MAX_BUF_SIZE) return false;
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
    if (blob_len < 28 || blob_len > MAX_BUF_SIZE) return false; 
    
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

    char* blob = (char*)malloc(MAX_BUF_SIZE);
    char* plaintext = (char*)malloc(MAX_BUF_SIZE);
    if (!blob || !plaintext) {
        printf_sgx("[Fatal] OOM: Failed to allocate %d bytes\n", MAX_BUF_SIZE);
        return -2;
    }
    
    char mac_hex[65];
    int final_dist = -1;
    int processed_nodes = 0;

    while (!pq.empty()) {
        int d = pq.top().first;
        std::string u = pq.top().second;
        pq.pop();

        if (u == t_id) {
            final_dist = d;
            break;
        }
        if (dist.find(u) != dist.end() && d > dist[u]) continue;

        std::string k = sha256_string(u + "_lookup");
        
        size_t real_len = 0;
        ocall_get_len(k.c_str(), &real_len);

        if (real_len == 0) continue;
        if (real_len > MAX_BUF_SIZE) {
            // 如果遇到超级大的节点，记录一下
            printf_sgx("[Warn] Node data too large: %lu > 20MB\n", real_len);
            continue; 
        }

        mac_hex[0] = '\0';
        ocall_fetch_data_optim(k.c_str(), blob, real_len, mac_hex);
        
        if (mac_hex[0] == '\0') continue;

        std::string hmac_key = sha256_string(u + "_hmac_key");
        if (!verify_hmac(blob, real_len, hmac_key, mac_hex)) {
             continue; 
        }

        std::string aes_key = sha256_string(u + "_aes_key");
        if (!decrypt_aes_native(blob, real_len, aes_key, plaintext)) continue;

        // [修复] 使用 int 读取
        int count = 0;
        memcpy(&count, plaintext, sizeof(int));
        
        EdgePayload* edges = (EdgePayload*)(plaintext + sizeof(int));
        
        if (count < 0 || (sizeof(int) + count * sizeof(EdgePayload)) > real_len) {
             continue;
        }
        
        processed_nodes++;

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

    printf_sgx("Result: %d | Nodes Processed: %d\n", final_dist, processed_nodes);
    return final_dist;
}