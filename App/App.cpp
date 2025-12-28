/* App/App.cpp */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;
std::map<std::string, std::pair<std::vector<char>, std::string>> SERVER_DB;
std::vector<std::string> ALL_NODES; 

struct __attribute__((packed)) EdgePayload {
    char p_v[65];      
    int weight;
    char next_key[65]; 
};

double get_time_sec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

std::string app_sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.length());
    SHA256_Final(hash, &sha256);
    char outputBuffer[65];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    return std::string(outputBuffer);
}

std::string app_hmac(const std::string& key_hex, const char* data, size_t len) {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char k_bytes[16];
    memset(k_bytes, 0, 16);
    memcpy(k_bytes, key_hex.c_str(), 16); 
    HMAC(EVP_sha256(), k_bytes, 16, (const unsigned char*)data, len, md_value, &md_len);
    char hex[65];
    for(unsigned int i = 0; i < md_len; i++)
        sprintf(hex + (i * 2), "%02x", md_value[i]);
    return std::string(hex);
}

void aes_encrypt_blob(const std::string& key_hex, const std::vector<char>& plaintext, std::vector<char>& output_blob) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    unsigned char aes_key[16];
    memset(aes_key, 0, 16);
    memcpy(aes_key, key_hex.c_str(), 16); 
    unsigned char iv[12];
    RAND_bytes(iv, 12); 

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv);

    std::vector<unsigned char> cipher_buf(plaintext.size() + 16); 
    EVP_EncryptUpdate(ctx, cipher_buf.data(), &len, (const unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, cipher_buf.data() + len, &len);
    ciphertext_len += len;

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    output_blob.clear();
    output_blob.insert(output_blob.end(), iv, iv + 12);
    output_blob.insert(output_blob.end(), tag, tag + 16);
    output_blob.insert(output_blob.end(), cipher_buf.begin(), cipher_buf.begin() + ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
}

void store_encrypted_node(const std::string& u_id, std::vector<EdgePayload>& neighbors) {
    std::vector<char> raw_payload;
    raw_payload.push_back((char)neighbors.size());
    for(auto& edge : neighbors) {
        char* p = (char*)&edge;
        for(size_t i=0; i<sizeof(EdgePayload); i++) raw_payload.push_back(p[i]);
    }
    // 最小 Padding
    if (raw_payload.size() < 1000) raw_payload.resize(1000, 0); 

    std::string lookup_key = app_sha256(u_id + "_lookup");
    std::string aes_key = app_sha256(u_id + "_aes_key"); 
    std::string hmac_key = app_sha256(u_id + "_hmac_key");

    std::vector<char> encrypted_blob;
    aes_encrypt_blob(aes_key, raw_payload, encrypted_blob);
    std::string mac = app_hmac(hmac_key, encrypted_blob.data(), encrypted_blob.size());

    SERVER_DB[lookup_key] = {encrypted_blob, mac};
}

// === 修改：返回真实长度 ===
#define MAX_BUF_SIZE 5000000 // 改为 5MB
// ... 在 ocall_fetch_data 中确保使用了这个宏 ...

void ocall_fetch_data(const char* key_ut, char* out_data, size_t* real_len, char* out_mac) {
    std::string k(key_ut);
    if (SERVER_DB.find(k) != SERVER_DB.end()) {
        auto& entry = SERVER_DB[k];
        std::vector<char>& blob = entry.first;
        std::string mac = entry.second;
        
        *real_len = blob.size();
        
        // 如果数据过大，必须截断，否则会溢出 SGX 边界导致崩溃
        // 并在 Enclave 端处理这个截断
        size_t cp_len = (*real_len > MAX_BUF_SIZE) ? MAX_BUF_SIZE : *real_len;
        
        memcpy(out_data, blob.data(), cp_len);
        strncpy(out_mac, mac.c_str(), 64);
        out_mac[64] = '\0';
    } else {
        *real_len = 0;
        out_mac[0] = '\0'; 
        out_data[0] = '\0';
    }
}

void ocall_print_string(const char *str) { printf("%s", str); }

void load_and_encrypt_dataset(const std::string& filename) {
    printf("Loading %s ... ", filename.c_str());
    std::ifstream file(filename);
    if (!file.is_open()) exit(1);

    std::map<std::string, std::vector<EdgePayload>> raw_graph;
    std::string line;
    int edges_count = 0;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ss(line);
        std::string u, v;
        ss >> u >> v;
        if (u == v) continue; 

        EdgePayload edge;
        std::string v_hash = app_sha256(v); 
        strncpy(edge.p_v, v_hash.c_str(), 64);
        edge.p_v[64] = '\0';
        edge.weight = (rand() % 10) + 1; 

        raw_graph[u].push_back(edge);
        if (raw_graph.find(v) == raw_graph.end()) raw_graph[v] = {};
        edges_count++;
    }

    for (auto& entry : raw_graph) {
        ALL_NODES.push_back(entry.first);
        std::string u_hash = app_sha256(entry.first); 
        store_encrypted_node(u_hash, entry.second);
    }
    printf("Done. Nodes: %lu, Edges: %d\n", ALL_NODES.size(), edges_count);
}

int main(int argc, char *argv[]) {
    std::string dataset = "wiki-Vote.txt";
    if (argc > 1) dataset = argv[1];

    int updated = 0;
    sgx_launch_token_t token = {0};
    sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    
    load_and_encrypt_dataset(dataset);

    // 修改 1: 打印提示改为 100
    printf("\nRunning 10 Queries...\n"); 
    printf("----------------------------------------------------------------\n");
    printf("%-20s | %-15s | %-20s\n", "Query (Start->End)", "Time (sec)", "HMAC Status");
    printf("----------------------------------------------------------------\n");

    double total_query_time = 0;
    int success_count = 0;
    srand(time(NULL));

    // 修改 2: 循环次数改为 100
    for (int i = 0; i < 10; i++) { 
        std::string start_node = ALL_NODES[rand() % ALL_NODES.size()];
        std::string end_node = ALL_NODES[rand() % ALL_NODES.size()];
        
        std::string s_hash = app_sha256(start_node);
        std::string t_hash = app_sha256(end_node);

        int min_dist = -1;
        
        double q_start = get_time_sec();
        ecall_dijkstra_search(global_eid, &min_dist, s_hash.c_str(), t_hash.c_str());
        double q_end = get_time_sec();

        double duration = q_end - q_start;
        total_query_time += duration;

        // 这里不需要打印每一行，否则屏幕会刷太快
        // 如果想看，可以保留；或者只打印前10个
        // printf("   Query %d ... \n", i+1 ...);
        
        if (min_dist != -1) success_count++;
    }

    printf("----------------------------------------------------------------\n");
    // 修改 3: 平均时间除以 100.0
    printf("   -> Avg Query Time: %.4f seconds\n", total_query_time / 10.0);
    // 修改 4: 连通性统计分母改为 100
    printf("   -> Connectivity: %d/10 found paths\n", success_count);
    
    printf("   [Ref] GraphShield Paper (wiki-Vote):\n");
    printf("         Avg Query Time: ~11.4 seconds\n");

    sgx_destroy_enclave(global_eid);
    return 0;
}