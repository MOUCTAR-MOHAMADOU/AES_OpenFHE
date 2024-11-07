#include "openfhe.h"

// Header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
using namespace std;

const std::string DATAFOLDER = "demoData";

vector<int64_t> readIntsFromFile(const string& filename) {
    vector<int64_t> vectorOfInts;
    ifstream file(filename);
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            vectorOfInts.push_back(stoll(line));
        }
        file.close();
    } else {
        cerr << "Could not open the file: " << filename << endl;
    }
    return vectorOfInts;
}

int main() {
    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << endl;
        return 1;
    }
    cout << "The cryptocontext has been deserialized." << endl;

    PublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY)) {
        cerr << "Could not read public key" << endl;
        return 1;
    }
    cout << "The public key has been deserialized." << endl;

    // Read the integers from the files and encode them
    vector<int64_t> vectorOfInts1 = readIntsFromFile("msg.txt");
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    vector<int64_t> vectorOfInts2 = readIntsFromFile("ka.txt");
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    cout << "Plaintext #1: " << plaintext1 << endl;
    cout << "Plaintext #2: " << plaintext2 << endl;

    // Encrypt the vectors
    auto ciphertext1 = cryptoContext->Encrypt(pk, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(pk, plaintext2);

    // Display the ciphertexts
    std::cout << "Ciphertext #1: " << ciphertext1 << std::endl;
    //std::cout << "Ciphertext #2: " << ciphertext2 << std::endl;


    
    cout << "Le message d'Alice msg.txt ainsi que sa clé ka.txt ont été bien chiffrés.." << endl;

    //std::cout << "OpenFHE version: " << OPENFHE_VERSION << std::endl;
    return 0;
}