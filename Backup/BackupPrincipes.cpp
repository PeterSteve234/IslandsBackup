#ifndef BACKUPPRINCIPES_H
#define BACKUPPRINCIPES_H

/* Standard C */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* POSIX / system calls */
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>

/* Advanced I/O / performance */
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

/* Extended attributes / ACLs */
#include <sys/xattr.h>
#include <acl/libacl.h>

/* Threading / concurrency */
#include <pthread.h>

/* Networking */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Compression / archiving */
#include <zlib.h>
#include <lzma.h>
#include <archive.h>
#include <archive_entry.h>

/* Crypto / checksums */
#include <openssl/evp.h>
#include <openssl/sha.h>

/* Utilities */
#include <stdbool.h>
#include <limits.h>
#include <sys/utsname.h>

#endif /* BACKUPPRINCIPES_H */

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

// ------------------------------------
// Classe principal
// ------------------------------------
class Backup {
private:
    std::string nomeArquivo;
    std::string tipoExtensao;
// criação de uma classe necessária: é preciso que seje iterado para detectar o tamanho
public:
static std::string human_read_size(uintmax_t bytes) { 
    const char* suf[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = static_cast<double>(bytes);
    while(size >= 1024.0 && i < 4) {size /= 1024.0; ++i; }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.2f %s", size, suf[i]);
    return std::string(buf);
};
    
    void lerCaminho() {
        std::cout << "Digite o nome do arquivo ou diretório: ";
        std::cin >> nomeArquivo;
    }

    
    void verificarTipo() const {
        if (fs::exists(nomeArquivo)) {
            if (fs::is_regular_file(nomeArquivo)) {
                std::cout << "✅ É um arquivo\n";

            } 
            else if (fs::is_directory(nomeArquivo)) {
                std::cout << "📁 É um diretório\n";
            } 
            else {
                std::cout << "⚠️ Existe, mas não é arquivo nem diretório\n";
            }
        } else {
            std::cout << "❌ Diretório ou arquivo inexistente\n";
        }
    }

    void confirmarOrigem() {
        std::string resposta;
        std::cout << nomeArquivo << " — este é o caminho correto? (s/n): ";
        std::cin >> resposta;

        if (resposta == "s" || resposta == "S") {
            if (fs::is_regular_file(nomeArquivo)) {
                std::cout << "Arquivo confirmado ✅\n";

            } 
            else if (fs::is_directory(nomeArquivo)) {
                std::cout << "Diretório confirmado 📁\n";
            }
        } 

        else {
            std::cout << "Ok, digite novamente.\n";
            lerCaminho();
            verificarTipo();
        }
    }

   
    std::string getNomeArquivo() const {
        return nomeArquivo;
    }
};

void iterar_diretorios() {

}

void verificar_tamanho_do_arquivo () {
    std::string nome_arquivo;
    std::string tamanho_arquivo;
    Backup b;
    b.lerCaminho();
    b.verificarTipo();
    std::cout << "Confirma este arquivo?" << std::endl;
    b.confirmarOrigem();
    b.human_read_size();

}

// ------------------------------------
// Função principal
// ------------------------------------
int main() {
    Backup b;
    b.lerCaminho();
    b.verificarTipo();
    b.confirmarOrigem();
    b.human_read_size();

    return 0;
}





