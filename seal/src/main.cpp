#include "seal/seal.h"
#include "example.h"
#include "linear_regression.h"
#include "interface.h"
#include <stdio.h>
#include <sstream>
#include <fstream>

int main(){

    LinearRegression model;

    model.loadCoefficients();
    model.printCoefficients();

    generateKeys();

    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    seal::SecretKey secretKey;
    seal::PublicKey publicKey;

    std::tie(parms, secretKey, publicKey) = loadKeys();

    seal::SEALContext context(parms);
    seal::Evaluator evaluator(context);
    seal::Encryptor encryptor(context, publicKey);

    model.encryptModel(context, publicKey, encryptor);

    std::map<std::string, uint64_t> featureMap;
    featureMap = enterFeatureValues();

    seal::Ciphertext prediction;
    prediction = model.predictEncrypted(featureMap, encryptor, evaluator);

    std::cout << "Size of prediction encypted: " << prediction.size() << std::endl;

    seal::Decryptor decryptor(context, secretKey);
    seal::Plaintext x_decrypted;
    decryptor.decrypt(prediction, x_decrypted);
    std::cout << "Decrypted prediction: " << std::stoi(x_decrypted.to_string(), nullptr, 16) << std::endl;

    return 0;
    
} 

