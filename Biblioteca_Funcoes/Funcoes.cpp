// =======================================================================================================

// SEGCXX_SECURITY_CONCEPTS.CPP - COLETÂNEA DE FUNÇÕES E CONCEITOS PARA C++ MODERNO E POSIX

// =======================================================================================================



#include <iostream>

#include <string>

#include <vector>

#include <map>

#include <set>

#include <memory>

#include <mutex>

#include <thread>

#include <atomic>

#include <chrono>

#include <cmath>

#include <cstdlib>

#include <cstring>

#include <cstdio>

#include <cassert>

#include <filesystem>

#include <regex>

#include <variant>

#include <optional>

#include <any>

#include <algorithm>

#include <numeric>

#include <functional>

#include <fstream>

#include <unistd.h>

#include <sys/types.h>

#include <sys/wait.h>

#include <sys/stat.h>

#include <sys/socket.h>

#include <fcntl.h>

#include <netdb.h>

#include <arpa/inet.h>

#include <openssl/evp.h>

#include <openssl/rand.h>

#include <openssl/ssl.h>

#include <openssl/err.h>

#include <pcap.h>



// =======================================================================================================

// MÓDULO: CORE - Tipos Básicos e Operações Fundamentais

// =======================================================================================================

int x = 10;

float f = 3.14f;

double d = 2.718;

char c = 'A';

bool ativo = true;

auto valor = 42;

decltype(x) y = 20;

sizeof(x);

typeid(x).name();



// =======================================================================================================

// MÓDULO: IO - Entrada e Saída

// =======================================================================================================

std::cout << "Texto" << std::endl;

std::cin >> x;

std::getline(std::cin, s);

std::cerr << "Erro!" << std::endl;

std::printf("Valor: %d\n", x);

std::fprintf(stderr, "Erro!\n");

std::snprintf(buf, 100, "Texto: %s", s.c_str());



// =======================================================================================================

// MÓDULO: STRING - Manipulação de Strings

// =======================================================================================================

std::string s = "texto";

s += " adicional";

s.append(" mais");

s.replace(0, 5, "novo");

s.erase(0, 3);

s.insert(2, "inserido");

s.find("texto");

s.substr(0, 4);

std::stoi("123");

std::to_string(456);

std::regex_match(s, std::regex(".*"));



// =======================================================================================================

// MÓDULO: VECTOR - Vetores Dinâmicos

// =======================================================================================================

std::vector<int> v = {1,2,3};

v.push_back(4);

v.pop_back();

v.size();

v.clear();

v.front();

v.back();

std::sort(v.begin(), v.end());

std::reverse(v.begin(), v.end());

std::find(v.begin(), v.end(), 2);



// =======================================================================================================

// MÓDULO: MAP - Mapas Associativos

// =======================================================================================================

std::map<std::string, int> m;

m["chave"] = 42;

m.at("chave");

m.find("chave");

m.erase("chave");

m.clear();



// =======================================================================================================

// MÓDULO: MEMORY - Gerenciamento de Memória

// =======================================================================================================

std::unique_ptr<int> p1 = std::make_unique<int>(10);

std::shared_ptr<int> p2 = std::make_shared<int>(20);

std::weak_ptr<int> p3 = p2;

int* raw = new int[100];

delete[] raw;



// =======================================================================================================

// MÓDULO: THREADING - Concorrência

// =======================================================================================================

std::thread t([](){ std::cout << "Thread\n"; });

t.join();

std::mutex mtx;

mtx.lock();

mtx.unlock();

std::lock_guard<std::mutex> lock(mtx);

std::atomic<int> counter(0);



// =======================================================================================================

// MÓDULO: EXCEPTION - Tratamento de Erros

// =======================================================================================================

try {

    throw std::runtime_error("Erro!");

} catch (const std::exception& e) {

    std::cerr << e.what();

}



// =======================================================================================================

// MÓDULO: FILESYSTEM - Manipulação de Arquivos

// =======================================================================================================

std::filesystem::exists("arquivo.txt");

std::filesystem::copy("a.txt", "b.txt");

std::filesystem::remove("arquivo.txt");

std::filesystem::create_directory("nova_pasta");



// =======================================================================================================

// MÓDULO: VARIANT - Tipos Genéricos

// =======================================================================================================

std::variant<int, std::string> v2 = "texto";

std::optional<int> opt = 42;

std::any a = 3.14;



// =======================================================================================================

// MÓDULO: ALGORITHM - Algoritmos STL

// =======================================================================================================

std::accumulate(v.begin(), v.end(), 0);

std::transform(v.begin(), v.end(), v.begin(), [](int x){ return x*2; });

std::count(v.begin(), v.end(), 2);

std::binary_search(v.begin(), v.end(), 3);

std::rotate(v.begin(), v.begin()+1, v.end());



// =======================================================================================================

// MÓDULO: MATH - Matemática

// =======================================================================================================

std::sqrt(9.0);

std::pow(2.0, 3.0);

std::abs(-5);

std::ceil(3.14);

std::floor(3.14);

std::round(3.5);

std::log(10);

std::exp(1);



// =======================================================================================================

// MÓDULO: POSIX - Sistema Operacional

// =======================================================================================================

pid_t pid = fork();

execvp("ls", args);

waitpid(pid, &status, 0);

getuid();

getpid();

int fd = open("arquivo.txt", O_RDONLY);

read(fd, buf, 100);

write(fd, buf, 100);

close(fd);



// =======================================================================================================

// MÓDULO: CRYPTO - OpenSSL

// =======================================================================================================

EVP_MD_CTX* ctx = EVP_MD_CTX_new();

EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

EVP_DigestUpdate(ctx, data, len);

EVP_DigestFinal_ex(ctx, hash, &hash_len);

EVP_MD_CTX_free(ctx);

RAND_bytes(buf, 32);



// =======================================================================================================

// MÓDULO: NETSEC - Libpcap

// =======================================================================================================

pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

pcap_loop(handle, 10, callback, NULL);

pcap_close(handle);



// =======================================================================================================

// FIM DO CATÁLOGO

// =======================================================================================================



// =======================================================================================================

// MÓDULO: STL_ADVANCED - Estruturas de Dados e Algoritmos Complexos

// =======================================================================================================



// === Contêineres Associativos (set, multiset) ===

std::set<int> unique_set = {5, 10, 15};

unique_set.insert(20);               // Adiciona valor único

unique_set.count(10);                // Checa se existe (retorna 0 ou 1)

unique_set.upper_bound(10);          // Maior elemento que 10 (iterador)

unique_set.lower_bound(10);          // Primeiro elemento >= 10 (iterador)

std::multiset<int> multi_set;

multi_set.equal_range(10);           // Intervalo de iteradores com chave 10



// === Contêineres de Sequência (deque, list) ===

std::deque<int> d;

d.push_front(1);                     // Adiciona no início (eficiente)

d.pop_front();                       // Remove do início (eficiente)

std::list<int> l;

l.push_back(1);                      // Adiciona no final

l.sort();                            // Ordenação nativa (eficiente para listas)

l.merge(l2);                         // Funde listas ordenadas



// === Contêineres Adaptadores (stack, queue, priority_queue) ===

std::stack<int> s_stack;

s_stack.push(1);                     // Empilha

s_stack.top();                       // Elemento no topo

s_stack.pop();                       // Desempilha

std::queue<int> q_queue;

q_queue.front();                     // Elemento frontal

q_queue.back();                      // Elemento traseiro

q_queue.push(1);                     // Enfileira

std::priority_queue<int> p_queue;

p_queue.top();                       // Maior elemento

p_queue.push(50);                    // Adiciona (mantém ordem de prioridade)



// === Contêineres Não-Ordenados (C++11) ===

std::unordered_map<std::string, int> um;

um.load_factor();                    // Fator de carga atual

um.rehash(100);                      // Força rehash

um.bucket_count();                   // Número de buckets

std::unordered_set<int> us;

us.reserve(50);                      // Sugere capacidade mínima



// === Iteradores e Ranges ===

v.begin();                           // Iterador para o primeiro elemento

v.end();                             // Iterador após o último

v.cbegin();                          // Iterador constante

v.rbegin();                          // Iterador reverso (do fim para o início)

std::next(v.begin(), 3);             // Avança o iterador N posições

std::distance(v.begin(), v.end());   // Distância entre iteradores

std::back_inserter(v);               // Iterador de inserção

for (int val : v) { }                // Range-based for loop (C++11)



// === Funções STL Adicionais ===

std::fill(v.begin(), v.end(), 0);    // Preenche intervalo com valor

std::min_element(v.begin(), v.end());// Encontra o menor elemento

std::max_element(v.begin(), v.end());// Encontra o maior elemento

std::is_sorted(v.begin(), v.end());  // Verifica se está ordenado

std::unique(v.begin(), v.end());     // Remove duplicatas adjacentes

std::set_intersection(v1.begin(), v1.end(), v2.begin(), v2.end(), std::back_inserter(v3)); // Interseção de conjuntos



// === Funções de Utility (C++11/17) ===

std::move(v);                        // Move semântica (Transferência de propriedade)

std::forward<T>(v);                  // Perfect forwarding

std::make_tuple(1, "a");             // Cria tupla

std::get<0>(t);                      // Acesso por índice em tupla

std::apply(func, t);                 // Aplica tupla como argumentos (C++17)

std::tie(x, y) = std::make_pair(1, 2); // Desempacotamento de pares

// =======================================================================================================

// MÓDULO: CONCURRENCY_ADVANCED - Futuros, Promessas e Atômicas

// =======================================================================================================



// === Futuros e Promessas (std::future, std::promise) ===

std::promise<int> p;

std::future<int> f = p.get_future();

p.set_value(42);                     // Seta o valor para o futuro

f.get();                             // Bloqueia e obtém o resultado

f.wait_for(std::chrono::seconds(1)); // Espera com timeout

std::async(std::launch::async, func); // Executa função assíncrona

std::packaged_task<int()> task(func);// Empacota função para ser executada



// === Condição e Sincronização ===

std::condition_variable cv;

std::unique_lock<std::mutex> ulock(mtx);

cv.wait(ulock, []{ return ready; }); // Espera por notificação e condição

cv.notify_one();                     // Notifica uma thread em espera

cv.notify_all();                     // Notifica todas as threads em espera

std::call_once(flag, func);          // Garante que a função é chamada uma única vez



// === Atômicas e Memória Ordering ===

std::atomic<bool> flag(false);

flag.store(true, std::memory_order_release); // Escrita atômica com ordenação

flag.load(std::memory_order_acquire);        // Leitura atômica com ordenação

flag.exchange(true);                         // Troca atômica (retorna valor antigo)

flag.compare_exchange_weak(expected, desired); // Comparação e Troca (CAS)

std::atomic_thread_fence(std::memory_order_seq_cst); // Barreira de memória



// === Semáforos e Barreiras (C++20) ===

// std::counting_semaphore<1> sem(1); // Semáforo básico

// sem.acquire();                     // Adquire permissão

// sem.release();                     // Libera permissão

// std::barrier bar(num_threads);

// bar.arrive_and_wait();             // Chega na barreira e espera



// === Funções de Thread Adicionais ===

std::this_thread::sleep_for(std::chrono::seconds(1)); // Thread dorme

std::this_thread::yield();           // Sugere ao SO que outra thread rode

std::thread::hardware_concurrency(); // Número de núcleos disponíveis

// =======================================================================================================

// MÓDULO: FILE_IO_CPP - Streams e I/O de Arquivos C++

// =======================================================================================================



// === Arquivo I/O Streams ===

std::fstream fs("file.txt", std::ios::in | std::ios::out);

fs.is_open();                        // Verifica se o stream está aberto

fs.good();                           // Verifica o estado geral (bom)

fs.eof();                            // Checa se atingiu o fim do arquivo

fs.fail();                           // Checa se falhou a leitura/escrita

fs.bad();                            // Checa se o stream está corrompido

fs.clear();                          // Limpa flags de erro

fs.seekg(100);                       // Move ponteiro de leitura

fs.tellg();                          // Obtém posição de leitura

fs.seekp(100);                       // Move ponteiro de escrita

fs.tellp();                          // Obtém posição de escrita

fs.write(buf, 100);                  // Escrita binária

fs.read(buf, 100);                   // Leitura binária



// === Streams de String e Buffer ===

std::stringstream ss("inicial");

ss << 10 << " " << 20;               // Escreve na stringstream

ss.str();                            // Obtém o conteúdo da stringstream como std::string

ss.clear();                          // Limpa flags

ss.str("");                          // Limpa o conteúdo da stringstream

std::istringstream is;               // Stream de entrada de string

std::ostringstream os;               // Stream de saída de string



// === Manipuladores e Formatação ===

std::cout << std::setw(10) << x;     // Define largura de campo

std::cout << std::setprecision(5);   // Define precisão de float

std::cout << std::hex << x;          // Formato hexadecimal

std::cout << std::dec << x;          // Formato decimal

std::cout << std::fixed;             // Notação de ponto fixo

std::cout << std::scientific;        // Notação científica

std::cin.setf(std::ios::skipws);     // Seta flag de formatação

std::cin.unsetf(std::ios::skipws);   // Remove flag



// === Funções de Manipulação de Arquivos (stdio.h) ===

std::remove("temp.txt");             // Deleta arquivo (C-style)

std::rename("old.txt", "new.txt");   // Renomeia arquivo (C-style)

std::tmpfile();                      // Cria arquivo temporário



// === Operações de Bytes (C++17) ===

std::byte b{0x42};

std::to_integer<int>(b);             // Converte byte para int

b << 1;                              // Shift de bit



// === Utilitários (time, random) ===

std::chrono::system_clock::now();    // Tempo atual

std::chrono::duration_cast<std::chrono::milliseconds>(d); // Conversão de duração

std::random_device rd;               // Fonte de entropia

std::mt19937 gen(rd());              // Gerador de Mersenne Twister

std::uniform_int_distribution<> distrib(1, 6); // Distribuição uniforme



// === Casting e Conversão ===

static_cast<int>(f);                 // Casting estático (seguro)

dynamic_cast<Subclass*>(ptr);        // Casting dinâmico (tempo de execução)

reinterpret_cast<int*>(ptr);         // Reinterpretação (alto risco)

const_cast<int*>(ptr);               // Remove const (alto risco)

// =======================================================================================================

// MÓDULO: POSIX_ADVANCED - Syscalls, Processos e Memória

// =======================================================================================================



// === Controle de Processos (Sistema) ===

wait(NULL);                          // Espera qualquer processo filho

WIFEXITED(status);                   // Macro: Checa se processo filho terminou normalmente

WEXITSTATUS(status);                 // Macro: Obtém código de saída do filho

alarm(10);                           // Envia sinal SIGALRM após N segundos

kill(pid, SIGTERM);                  // Envia sinal para o processo

setuid(1000);                        // Define UID (Troca de privilégios)

getegid();                           // Obtém ID do grupo efetivo

geteuid();                           // Obtém ID do usuário efetivo

nice(5);                             // Altera prioridade do processo



// === I/O e FDs Avançados ===

dup(fd);                             // Duplica o File Descriptor

lseek(fd, 0, SEEK_END);              // Move ponteiro do FD

ioctl(fd, request, arg);             // Operações de I/O em FDs (ex: sockets, terminais)

fcntl(fd, F_SETFD, FD_CLOEXEC);      // Manipula flags do FD (ex: fechar em exec)

fsync(fd);                           // Força a escrita de dados para o disco

mkdir("pasta", 0755);                // Cria diretório

rmdir("pasta");                      // Remove diretório



// === Memória e Mapeamento ===

mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // Mapeia memória (compartilhada ou anônima)

munmap(addr, 1024);                  // Desmapeia a memória

mlock(addr, 1024);                   // Bloqueia páginas na RAM (para chaves criptográficas)

mprotect(addr, 1024, PROT_NONE);     // Altera permissões de proteção de memória

shm_open("/shm_name", O_CREAT | O_RDWR, 0666); // Cria/Abre memória compartilhada

shm_unlink("/shm_name");             // Remove objeto de memória compartilhada



// === Rede e Sockets (Detalhes) ===

getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen); // Obtém opções do socket

setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)); // Define opções do socket

getnameinfo(&sa, sa_len, host, hlen, serv, slen, flags); // Conversão bidirecional (IP <-> Nome)

getaddrinfo("google.com", "http", &hints, &res); // Resolução DNS (moderno)

freeaddrinfo(res);                   // Libera lista de resultados DNS

htons(port);                         // Conversão Host -> Rede (Short)

ntohl(ip_addr);                      // Conversão Rede -> Host (Long)

recvfrom(fd, buf, len, 0, &src_addr, &addrlen); // Recebe UDP (datagrama)



// === Segurança e Logging POSIX ===

syslog(LOG_ERR, "Erro crítico: %m"); // Escreve no log do sistema (syslog)

umask(022);                          // Define máscara de permissão de criação de arquivo

setpgid(0, 0);                       // Define Process Group ID (Controle de sessão)

// =======================================================================================================

// MÓDULO: CRYPTO_ADVANCED - Criptografia Simétrica e Assimétrica

// =======================================================================================================



// === Hashing e MAC Avançado ===

HMAC_CTX_new();                      // Criação de contexto HMAC

HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL); // Inicialização HMAC

HMAC_Update(hmac_ctx, data, len);    // Update HMAC

HMAC_Final(hmac_ctx, tag, &tag_len); // Finaliza HMAC

PKCS5_PBKDF2_HMAC(pass, pass_len, salt, salt_len, 100000, EVP_sha256(), key_len, key); // PBKDF2



// === Criptografia Simétrica (AES/Chacha20) ===

EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); // Inicializa ENCRYPT

EVP_EncryptUpdate(ctx, out, &out_len, in, in_len); // Encrypt Update

EVP_EncryptFinal_ex(ctx, out, &out_len); // Encrypt Final

EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); // Inicializa DECRYPT

EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag); // GCM: Seta Tag (para Decrypt)

EVP_CIPHER_CTX_set_padding(ctx, 0);  // Desativa padding (para AES)



// === Criptografia Assimétrica (RSA) ===

RSA_generate_key_ex(rsa_key, 2048, pub_exp, NULL); // Gera par de chaves RSA

RSA_public_encrypt(len, in, out, rsa_key, RSA_PKCS1_PADDING); // Encrypt com chave pública

RSA_private_decrypt(len, in, out, rsa_key, RSA_PKCS1_PADDING); // Decrypt com chave privada

RSA_sign(NID_sha256, hash, hash_len, sig, &sig_len, rsa_key); // Assinatura digital

X509_free(cert);                     // Libera certificado X509



// === Utilitários de Segurança ===

ERR_peek_error();                    // Obtém último erro OpenSSL

SSL_load_error_strings();            // Carrega strings de erro

SSL_CTX_new(SSLv23_client_method()); // Cria contexto TLS/SSL

SSL_new(ssl_ctx);                    // Cria sessão SSL

SSL_connect(ssl);                    // Handshake TLS

SSL_write(ssl, data, len);           // Escreve via TLS

SSL_read(ssl, buf, len);             // Lê via TLS

SSL_get_verify_result(ssl);          // Obtém resultado da verificação de certificado