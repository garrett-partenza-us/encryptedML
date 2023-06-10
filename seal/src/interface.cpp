#include <map>
#include <vector>
#include <iostream>
#include <string>
#include "seal/seal.h"
#include <sstream>
#include <fstream>
#include <tuple>

std::map<std::string, uint64_t> enterFeatureValues(){

    std::map<std::string, uint64_t> featureMap;

    // Hardcoded feature names and coefficients
    std::string featureNames[] = {"age", "sex", "bmi", "children", "smoker", "region"};

    std::cout << "Enter feature values:\n";
    for (const auto& featureName : featureNames) {
        uint64_t coefficient;

        std::cout << featureName << " coefficient: ";
        std::cin >> coefficient;

        // Insert feature and coefficient into the map
        featureMap[featureName] = coefficient;
    }

    return featureMap;
}

int generateKeys() {

    size_t polyModulusDegree = 8192;
    std::vector<int> coeffModulusBits = {54};
    int plainModulus = 65537;

    // Set up the SEAL context
    std::cout << "Generating context..." << std::endl;
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(polyModulusDegree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(polyModulusDegree, coeffModulusBits));
    parms.set_plain_modulus(plainModulus);
    seal::SEALContext context(parms);

    // Generate the secret key
    std::cout << "Generating secret key..." << std::endl;
    seal::KeyGenerator keyGen(context);
    seal::SecretKey secretKey = keyGen.secret_key();

    // Generate the public key
    std::cout << "Generating public key..." << std::endl;
    seal::PublicKey publicKey;
    keyGen.create_public_key(publicKey);
    
    // Save the secret key
    std::cout << "Saving secret key..." << std::endl;
    std::ostringstream ss;
    secretKey.save(ss, seal::compr_mode_type::none);
    std::string encoded = ss.str();
    std::ofstream file;
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/secret.bin", std::ios::binary);
    file.write(encoded.c_str(), encoded.size());
    file.close();
    file.clear();
    ss.str("");
    
    // Save the public key
    std::cout << "Saving public key..." << std::endl;
    publicKey.save(ss, seal::compr_mode_type::none);
    encoded = ss.str();
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/public.bin", std::ios::binary);
    file.write(encoded.c_str(), encoded.size());
    file.close();
    file.clear();
    ss.str("");

    // Save the parameters
    std::cout << "Saving parameters..." << std::endl;
    parms.save(ss, seal::compr_mode_type::none);
    encoded = ss.str();
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/parms.bin", std::ios::binary);
    file.write(encoded.c_str(), encoded.size());
    file.close();

    return 0;
}

std::tuple<seal::EncryptionParameters, seal::SecretKey, seal::PublicKey> loadKeys() {

    // Load parameters
    std::cout << "Loading parameters..." << std::endl;
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    std::ifstream file;
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/parms.bin", std::ios::binary);
    std::stringstream ss;
    ss << file.rdbuf();
    parms.load(ss);
    ss.str("");
    file.close();
    file.clear();

    // Create context
    seal::SEALContext context(parms);

    // Load secret key
    std::cout << "Loading secret key..." << std::endl;
    seal::SecretKey secretKey;
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/secret.bin", std::ios::binary);
    ss << file.rdbuf();
    secretKey.load(context, ss);
    ss.str("");
    file.close();
    file.clear();

    // Load public key
    std::cout << "Loading public key..." << std::endl;
    seal::PublicKey publicKey;
    file.open("/Users/garrett.partenza/Desktop/Homo/seal/keys/public.bin", std::ios::binary);
    ss << file.rdbuf();
    publicKey.load(context, ss);
    file.close();

    std::tuple<seal::EncryptionParameters, seal::SecretKey, seal::PublicKey> result(parms, secretKey, publicKey);

    return result;

}

int predictEncrypted(std::map<std::string, int> featureMap, seal::Evaluator evaluator) {
    
}