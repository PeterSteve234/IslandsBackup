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

// Minimal, portable implementation for testing/building
#include "..\Headers\BackupPrincipes.h"
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

void Arquivo() {
    std::string nome_arquivo;
    std::cout << "Digite o nome do arquivo ou diretório: ";
    if (!(std::cin >> nome_arquivo)) {
        std::cerr << "Erro ao ler o nome do arquivo." << std::endl;
        return;
    }

    std::error_code ec;
    if (fs::exists(nome_arquivo, ec)) {
        if (fs::is_regular_file(nome_arquivo, ec)) {
            std::cout << "É um arquivo." << std::endl;
        } else if (fs::is_directory(nome_arquivo, ec)) {
            std::cout << "É um diretório." << std::endl;
        } else {
            std::cout << "Existe, mas não é arquivo nem diretório regular." << std::endl;
        }
    } else {
        std::cout << "Diretório/arquivo inexistente ou inacessível." << std::endl;
    }
}

void origem() {
    // stub: implementar origem do backup
}

void destino() {
    // stub: implementar destino do backup
}

void verificar_tamanho_do_arquivo() {
    // stub: implementar verificação de tamanho
}

int main() {
    std::cout << "IslandsBackup - teste básico\n";
    Arquivo();
    return 0;
}
    std::cout << "é um diretorio" << std::endl;
