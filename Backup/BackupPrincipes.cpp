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

public:
    // Função estática para converter tamanho de bytes em formato legível
    static std::string human_read_size(uintmax_t bytes) {
        const char* suf[] = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double size = static_cast<double>(bytes);
        while (size >= 1024.0 && i < 4) {
            size /= 1024.0;
            ++i;
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.2f %s", size, suf[i]);
        return std::string(buf);
    }

    void lerCaminho() {
        std::cout << "Digite o nome do arquivo ou diretório: ";
        std::cin >> nomeArquivo;
    }

    void verificarTipo() const {
        if (fs::exists(nomeArquivo)) {
            if (fs::is_regular_file(nomeArquivo)) {
                std::cout << "✅ É um arquivo\n";
            } else if (fs::is_directory(nomeArquivo)) {
                std::cout << "📁 É um diretório\n";
            } else {
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
            } else if (fs::is_directory(nomeArquivo)) {
                std::cout << "Diretório confirmado 📁\n";
            }
        } else {
            std::cout << "Ok, digite novamente.\n";
            lerCaminho();
            verificarTipo();
        }
    }

    void mostrarTamanho() const {
        if (fs::exists(nomeArquivo) && fs::is_regular_file(nomeArquivo)) {
            uintmax_t tamanho = fs::file_size(nomeArquivo);
            std::cout << "Tamanho: " << human_read_size(tamanho) << "\n";
        } else {
            std::cout << "Não é um arquivo válido para medir o tamanho.\n";
        }
    }

    void iterarDiretorios() const {
        if (fs::exists(nomeArquivo) && fs::is_directory(nomeArquivo)) {
            std::cout << "Conteúdo do diretório:\n";
            for (const auto& entry : fs::directory_iterator(nomeArquivo)) {
                std::cout << " - " << entry.path().filename().string();
                if (fs::is_regular_file(entry)) {
                    std::cout << " (" << human_read_size(fs::file_size(entry)) << ")";
                }
                std::cout << "\n";
            }
        } else {
            std::cout << "Não é um diretório válido.\n";
        }
    }
};

// ------------------------------------
// Função principal
// ------------------------------------
int main() {
    Backup b;
    b.lerCaminho();
    b.verificarTipo();
    b.confirmarOrigem();
    b.mostrarTamanho();
    b.iterarDiretorios();

    return 0;
}

#endif
