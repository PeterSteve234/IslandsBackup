#ifndef BACKUPPRINCIPES_H
#define BACKUPPRINCIPES_H

/* Standard C */
#include <stdio.h>      // I/O básico, fprintf, fopen, etc.
#include <stdlib.h>     // malloc, free, exit
#include <string.h>     // strcpy, strcat, strcmp
#include <stdint.h>     // tipos inteiros com tamanho garantido
#include <errno.h>      // errno

/* POSIX / system calls */
#include <unistd.h>     // read, write, close, unlink, getopt
#include <fcntl.h>      // open, O_* flags, fcntl
#include <sys/types.h>
#include <sys/stat.h>   // stat, fstat, mkdir, chmod
#include <dirent.h>     // opendir, readdir, closedir
#include <utime.h>      // utime, utimbuf
#include <pwd.h>        // getpwuid
#include <grp.h>        // getgrgid
#include <time.h>       // time, strftime
#include <signal.h>     // manejo de sinais
#include <sys/wait.h>   // waitpid

/* Advanced I/O / performance */
#include <sys/sendfile.h> // sendfile (zero-copy, Linux)
#include <sys/mman.h>     // mmap
#include <sys/statvfs.h>  // estatísticas de FS (espaço livre)

/* Extended attributes / ACLs */
#include <sys/xattr.h>    // getxattr/setxattr (Linux)
#include <acl/libacl.h>   // ACLs (se necessário)

/* Threading / concurrency */
#include <pthread.h>      // pthreads, mutex, cond

/* Networking (para backup remoto) */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>        // getaddrinfo

/* Compression / archiving (libs externas) */
/* Requer link com -lz, -llzma, -larchive, etc. */
#include <zlib.h>         // gzip/deflate
#include <lzma.h>         // xz/lzma (opcional)
#include <archive.h>      // libarchive (tar/zip/auto)
#include <archive_entry.h>

/* Crypto / checksums (libs externas) */
/* Requer link com -lcrypto (OpenSSL) ou libs como libgcrypt */
#include <openssl/evp.h>   // cifragem/decifragem
#include <openssl/sha.h>   // SHA checksums

/* Utilities */
#include <stdbool.h>      // bool
#include <limits.h>       // PATH_MAX
#include <sys/utsname.h>  // uname (info do sistema)

#endif /* BACKUPPRINCIPES_H */

#include <filesystem>
#include <iostream>
	

namespace fs= std::filesystem;

std::string nome_arquivo;
std::string diretorio;
std::string tipo_extensao;


void Arquivo() {
    std::cout << "digite o nome do arquivo" << nome_arquivo << std::endl;
    std::cin >> nome_arquivo;

    if(fs::exists(nome_arquivo) ) {
    std::cout << "é um arquivo" << std::endl;
    } 

    else if(fs::is_directory(nome_arquivo)){
    std::cout << "é um diretorio" << std::endl;
    }

    else {
    std::cout << "Diretório corrompido ou inexistente" << std::endl;
    }
}

void origem_destino () {

}

void verificar_tamanho_do_arquivo () {

}



int main () {
	// implementação futura
}