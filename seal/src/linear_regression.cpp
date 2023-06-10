#include "linear_regression.h"
#include <sstream>
#include <string>
#include "seal/seal.h"

LinearRegression::LinearRegression() {}

int LinearRegression::loadCoefficients()
{

    std::ifstream file("/Users/garrett.partenza/Desktop/Homo/linear_regression_model.csv");

    if (!file.is_open())
    {
        std::cout << "Failed to open the file" << std::endl;
        return -1;
    }

    std::cout << "Loading model coefficients..." << std::endl;
    std::string line;
    std::getline(file, line);
    while (std::getline(file, line))
    {
        std::stringstream ss(line);
        std::string featureName, coefficientStr;
        std::getline(ss, featureName, ',');
        std::getline(ss, coefficientStr);
        this->coefficients[featureName] = static_cast<uint64_t>(std::stoi(coefficientStr));
    }

    return 0;
}

int LinearRegression::predictPlaintext(const std::map<std::string, int> &features)
{

    int prediction = 0;

    for (const auto &entry : features)
    {
        const std::string &featureName = entry.first;
        int featureValue = entry.second;

        if (coefficients.count(featureName) > 0)
        {
            int coefficient = coefficients.at(featureName);
            prediction += coefficient * featureValue;
        }
    }

    return prediction;
}

int LinearRegression::encryptModel(seal::SEALContext &context, seal::PublicKey &publicKey, seal::Encryptor &encryptor)
{

    for (const auto &entry : this->coefficients)
    {
        const std::string &key = entry.first;
        const uint64_t value = entry.second;

        std::string hexString = seal::util::uint_to_hex_string(&value, std::size_t(1));

        seal::Plaintext plaintext;
        seal::Plaintext x_plain(hexString);

        seal::Ciphertext x_encrypted;
        encryptor.encrypt(x_plain, x_encrypted);
        this->encryptedCoefficients[key] = x_encrypted;
    }

    return 0;
}

seal::Ciphertext LinearRegression::predictEncrypted(const std::map<std::string, uint64_t> &features, seal::Encryptor &encryptor, seal::Evaluator &evaluator)
{

    seal::Ciphertext prediction;
    seal::Ciphertext temp;
    encryptor.encrypt_zero(prediction);
    encryptor.encrypt_zero(temp);
    seal::Plaintext plaintext;
    std::string hexString;

    for (const auto &entry : features)
    {
        const std::string &featureName = entry.first;
        uint64_t featureValue = entry.second;
        seal::Ciphertext coefficient = this->encryptedCoefficients.at(featureName);
        seal::Plaintext plaintext;
        hexString = seal::util::uint_to_hex_string(&featureValue, std::size_t(1));
        plaintext = hexString;
        evaluator.multiply_plain(coefficient, plaintext, temp);
        evaluator.add_inplace(prediction, temp);
    }

    return prediction;
}

void LinearRegression::printCoefficients()
{
    for (const auto &entry : this->coefficients)
    {
        std::cout << "Feature: " << entry.first << ", Coefficient: " << entry.second << std::endl;
    }
}