#ifndef LINEAR_REGRESSION_H
#define LINEAR_REGRESSION_H

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include "seal/seal.h"

class LinearRegression {

private:
    std::map<std::string, uint64_t> coefficients;
    std::map<std::string, seal::Plaintext> base64Coefficients;
    std::map<std::string, seal::Ciphertext> encryptedCoefficients;

public:
    LinearRegression();
    int loadCoefficients();
    int predictPlaintext(const std::map<std::string, int>& features);
    void printCoefficients();
    int encryptModel(seal::SEALContext& context, seal::PublicKey& publicKey, seal::Encryptor& encryptor);
    seal::Ciphertext predictEncrypted(const std::map<std::string, uint64_t>& features, seal::Encryptor& encryptor, seal::Evaluator& evaluator);
};

#endif // LINEAR_REGRESSION_H`