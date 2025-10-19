#ifndef BACKUPPRINCIPES_H
#define BACKUPPRINCIPES_H

#include <iostream>
#include <string>
#include <filesystem>

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

void iterar_diretorios() {
std::string identificador = ler_caminho();
    if(fs::is_directory(identificador) {
        for(const auto& entry : std::filesystem::directory_iterator(identificador)) {
        std::cout << entry.ṕath().filename() << std::endl;
        }
    return 0;
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
    b.iterar_diretorios();

    return 0;
}





