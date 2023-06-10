#ifndef INTERFACE_H
#define INTERFACE_H

#include <map>
#include <string>

std::map<std::string, uint64_t> enterFeatureValues();
int generateKeys();
std::tuple<seal::EncryptionParameters, seal::SecretKey, seal::PublicKey> loadKeys();
int predictEncrypted(std::map<std::string, int> featureMap, seal::Evaluator evaluator);


#endif // INTERFACE_H