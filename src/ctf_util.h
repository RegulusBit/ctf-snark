//
// Created by reza on 2/3/18.
//

#ifndef LIBSNARK_TUTORIAL_CTF_UTIL_H
#define LIBSNARK_TUTORIAL_CTF_UTIL_H

#include <string>
#include <vector>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

using namespace libsnark;
typedef libff::Fr<libff::default_ec_pp> default_FieldT;



class prover_profile
{
public:
    prover_profile(std::string _name, std::string _id);
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> generate_public_keys(void);
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> prove_witness(const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& _keypair,
                                                                  const libff::bit_vector _left_bv,
                                                                  const libff::bit_vector _right_bv,
                                                                  const libff::bit_vector _hash_bv);
    void verify_witness(const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& _keypair,
                        const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>& _proof);
    static void initialization(void);
    std::string get_name(){return prover_name;}
    std::string get_id(){return prover_id;}
private:
    std::string prover_name;
    std::string prover_id;
    protoboard<default_FieldT> pb;
    digest_variable<default_FieldT> left;
    digest_variable<default_FieldT> right;
    digest_variable<default_FieldT> output;
    sha256_two_to_one_hash_gadget<default_FieldT> f;
};

#endif //LIBSNARK_TUTORIAL_CTF_UTIL_H
