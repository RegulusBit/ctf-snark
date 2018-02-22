//
// Created on 2/3/18. test implementation of SHA256 verification based on CTF challenge.
//

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include "ctf_util.h"
#include <iostream>

#include <string>

int main()
{

    std::cout << "initializing circuit generation using gadgetlib1 hashing libraries..." << std::endl;
    prover_profile prover("name", "id");
    prover_profile::initialization();
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keys = prover.generate_public_keys();

    /* concatenate block = left || right */
    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d84dc8678281e8957a409ec148e6cffbe8afe6ba4f9c6f1978dd7af7e9}, 256);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0}, 256);
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1}, 256);

    std::string s;
    for (auto i: left_bv) {
        if(i)
            s.push_back('1');
        else
            s.push_back('0');
        std::cout << i;
    }
    std::cout << std::endl << s;
    std::reverse(s.begin(), s.end());
    std::cout << std::endl << s;


    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> _proof = prover.prove_witness(keys, left_bv, right_bv, hash_bv);

    prover.verify_witness(keys, _proof);

    return 0;
}
