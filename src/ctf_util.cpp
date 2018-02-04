//
// Created by reza on 2/3/18.
//

#include "ctf_util.h"
#include <cstdlib>

using namespace libsnark;


prover_profile::prover_profile(std::string _name, std::string _id)
: left(pb, SHA256_digest_size, "left"),
  right(pb, SHA256_digest_size, "right"),
  output(pb, SHA256_digest_size, "output"),
  f(pb, left, right, output, "f")
{
    //initialize prover
    if(_name.empty() && _id.empty())   // checks if both name and id of attendant is empty, attendant must have identifier
        abort();
    prover_name = _name;
    prover_id = _id;


    f.generate_r1cs_constraints();
    std::cout << "Number of constraints for sha256_two_to_one_hash_gadget: " << pb.num_constraints() << std::endl;
}

void prover_profile::initialization()
{
    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
}

r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> prover_profile::generate_public_keys()
{
    libff::print_header("R1CS ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(pb.get_constraint_system());
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");
    return keypair;
}

r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> prover_profile::prove_witness(const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& _keypair,
                                                                              const libff::bit_vector _left_bv,
                                                                              const libff::bit_vector _right_bv,
                                                                              const libff::bit_vector _hash_bv)
{
    left.generate_r1cs_witness(_left_bv);
    right.generate_r1cs_witness(_right_bv);
    f.generate_r1cs_witness();
    output.generate_r1cs_witness(_hash_bv);



    assert(pb.is_satisfied());

    libff::print_header("R1CS ppzkSNARK Prover");
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(_keypair.pk, pb.primary_input(), pb.auxiliary_input());
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");
    return proof;
}

void prover_profile::verify_witness(const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& _keypair, const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>& _proof)
{
    libff::print_header("R1CS ppzkSNARK Verifier");
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(_keypair.vk, pb.primary_input(), _proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
}