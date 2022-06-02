#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_generator.h"
#include "secp256k1_rangeproof.h"
#include "secp256k1_preallocated.h"
#include "secp256k1_surjectionproof.h"

#ifndef SECP256K1_CONTEXT_ALL
#define SECP256K1_CONTEXT_ALL SECP256K1_CONTEXT_NONE | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
#endif

int ecdh(unsigned char *output, const unsigned char *pubkey, const unsigned char *scalar)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pubkey point;
  if (!secp256k1_ec_pubkey_parse(ctx, &point, pubkey, 33))
    return 0;
  int ret = secp256k1_ecdh(ctx, output, &point, scalar, NULL, NULL);
  secp256k1_context_destroy(ctx);
  return ret;
}

int generator_generate(unsigned char *generator, const unsigned char *random_seed32)
{
  secp256k1_generator gen;
  memcpy(&(gen.data), generator, 64);
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_generator_generate(ctx, &gen, random_seed32);
  if (ret == 1)
  {
    memcpy(generator, gen.data, 64);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int generator_generate_blinded(unsigned char *gen_data, const unsigned char *key32, const unsigned char *blind32)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_generator gen;
  memcpy(&(gen.data), gen_data, 64);
  int ret = secp256k1_generator_generate_blinded(ctx, &gen, key32, blind32);
  if (ret == 1)
  {
    memcpy(gen_data, gen.data, 64);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int generator_parse(unsigned char *gen_data, const unsigned char *input)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_generator gen;
  memcpy(&(gen.data), gen_data, 64);
  int ret = secp256k1_generator_parse(ctx, &gen, input);
  if (ret == 1)
  {
    memcpy(gen_data, &(gen.data), 64);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int generator_serialize(unsigned char *output, const unsigned char *gen_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_generator gen;
  memcpy(&(gen.data), gen_data, 64);
  int ret = secp256k1_generator_serialize(ctx, output, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_blind_generator_blind_sum(const uint64_t *values, const unsigned char* const *generator_blinds, unsigned char **blind_factors, size_t n_total, size_t n_inputs, unsigned char * bytes_out)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  blind_factors[n_total - 1] = bytes_out;
  int ret = secp256k1_pedersen_blind_generator_blind_sum(ctx, values, generator_blinds, (unsigned char *const *)blind_factors, n_total, n_inputs);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_commitment_parse(unsigned char *commit_data, const unsigned char *input)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  memcpy(&(commit.data), commit_data, 64);
  int ret = secp256k1_pedersen_commitment_parse(ctx, &commit, input);
  memcpy(commit_data, &(commit.data), 64);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_commitment_serialize(unsigned char *output, unsigned char *commit_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  memcpy(&(commit.data), commit_data, 64);
  int ret = secp256k1_pedersen_commitment_serialize(ctx, output, &commit);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_commit(unsigned char *commit_data, const unsigned char *blind, uint64_t value, const unsigned char *generator_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  memcpy(&(commit.data), commit_data, 64);
  secp256k1_generator gen;
  memcpy(&(gen.data), generator_data, 64);
  int ret = secp256k1_pedersen_commit(ctx, &commit, blind, value, &gen);
  memcpy(commit_data, &(commit.data), 64);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_blind_sum(unsigned char *sum, const unsigned char *const *blinds, size_t n, size_t npos)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_pedersen_blind_sum(ctx, sum, blinds, n, npos);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_verify_tally(const unsigned char *const *commits_data, size_t n_commits, const unsigned char *const *negcommits_data, size_t n_negcommits)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commits[n_commits];
  secp256k1_pedersen_commitment negcommits[n_negcommits];
  secp256k1_pedersen_commitment *p_commits[n_commits];
  secp256k1_pedersen_commitment *p_negcommits[n_negcommits];
  for (int i = 0; i < (int)n_commits; ++i)
  {
    memcpy(&(commits[i].data), commits_data[i], 64);
    p_commits[i] = &commits[i];
  }
  for (int i = 0; i < (int)n_negcommits; ++i)
  {
    memcpy(&(negcommits[i].data), negcommits_data[i], 64);
    p_negcommits[i] = &negcommits[i];
  }
  int ret = secp256k1_pedersen_verify_tally(ctx, (const secp256k1_pedersen_commitment * const*)p_commits, n_commits, (const secp256k1_pedersen_commitment * const*)p_negcommits, n_negcommits);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_sign(unsigned char *proof, size_t *plen, uint64_t min_value, const unsigned char *commit_data, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value, const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const unsigned char *generator_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  memcpy(&(commit.data), commit_data, 64);
  secp256k1_generator gen;
  memcpy(&(gen.data), generator_data, 64);
  int ret = secp256k1_rangeproof_sign(ctx, proof, plen, min_value, &commit, blind, nonce, exp, min_bits, value, msg_len > 0 ? message : NULL, msg_len, extra_commit_len > 0 ? extra_commit : NULL, extra_commit_len, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_info(int *exp, int *mantissa, uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_rangeproof_info(ctx, exp, mantissa, min_value, max_value, proof, plen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_verify(uint64_t *min_value, uint64_t *max_value, const unsigned char *commit_data, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const unsigned char *generator_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  memcpy(&(commit.data), commit_data, 64);
  secp256k1_generator gen;
  memcpy(&(gen.data), generator_data, 64);
  int ret = secp256k1_rangeproof_verify(ctx, min_value, max_value, &commit, proof, plen, extra_commit, extra_commit_len, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_rewind(unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce, uint64_t *min_value, uint64_t *max_value, const unsigned char *commit_data, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const unsigned char *generator_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  secp256k1_generator gen;
  memcpy(&(gen.data), generator_data, 64);
  memcpy(&(commit.data), commit_data, 64);
  int ret = secp256k1_rangeproof_rewind(ctx, blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commit, proof, plen, extra_commit, extra_commit_len, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_parse(size_t *n_inputs, unsigned char *used_inputs, unsigned char *data, const unsigned char *input, size_t inputlen) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_surjectionproof proof;
  memcpy(&(proof.n_inputs), n_inputs, sizeof(proof.n_inputs));
  memcpy(&(proof.used_inputs), used_inputs, 32);
  memcpy(&(proof.data), data, 8224);
  int ret = secp256k1_surjectionproof_parse(ctx, &proof, input, inputlen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_serialize(unsigned char *output, size_t *outputlen, size_t *n_inputs, const unsigned char *used_inputs, const unsigned char *data) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  secp256k1_surjectionproof proof;
  memcpy(&(proof.n_inputs), n_inputs, sizeof(proof.n_inputs));
  memcpy(&(proof.used_inputs), used_inputs, 32);
  memcpy(&(proof.data), data, 8224);
  int ret = secp256k1_surjectionproof_serialize(ctx, output, outputlen, &proof);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_initialize(size_t *n_inputs, unsigned char *used_inputs, unsigned char *data, size_t *input_index, const unsigned char * const *input_tags_data, const size_t n_input_tags, const size_t n_input_tags_to_use, const unsigned char *output_tag_data, const size_t n_max_iterations, const unsigned char *random_seed32) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_surjectionproof proof;
  secp256k1_fixed_asset_tag input_tags[n_input_tags];
  for (int i = 0; i < (int)n_input_tags; ++i) {
    memcpy(&(input_tags[i].data), input_tags_data[i], 32);
  }
  secp256k1_fixed_asset_tag output_tag;
  memcpy(&(output_tag.data), output_tag_data, 32);
  int ret = secp256k1_surjectionproof_initialize(ctx, &proof, input_index, input_tags, n_input_tags, n_input_tags_to_use, &output_tag, n_max_iterations, random_seed32);
  if (ret > 0) {
    memcpy(n_inputs, &(proof.n_inputs), sizeof(proof.n_inputs));
    memcpy(used_inputs, &(proof.used_inputs), 32);
    memcpy(data, &(proof.data), 8224);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_generate(size_t *n_inputs, unsigned char *used_inputs, unsigned char *data, const unsigned char * const *ephemeral_input_tags_data, const size_t n_ephemeral_input_tags, const unsigned char *ephemeral_output_tag_data, size_t input_index, const unsigned char *input_blinding_key, const unsigned char *output_blinding_key) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_surjectionproof proof;
  memcpy(&(proof.n_inputs), n_inputs, sizeof(proof.n_inputs));
  memcpy(&(proof.used_inputs), used_inputs, 32);
  memcpy(&(proof.data), data, 8224);
  secp256k1_generator ephemeral_input_tags[n_ephemeral_input_tags];
  for (int i = 0; i < (int)n_ephemeral_input_tags; ++i) {
    memcpy(&(ephemeral_input_tags[i].data), ephemeral_input_tags_data[i], 64);
  }
  secp256k1_generator ephemeral_output_tag;
  memcpy(&(ephemeral_output_tag.data), ephemeral_output_tag_data, 64);
  int ret = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_ephemeral_input_tags, &ephemeral_output_tag, input_index, input_blinding_key, output_blinding_key);
  if (ret == 1) {
    memcpy(n_inputs, &(proof.n_inputs), sizeof(proof.n_inputs));
    memcpy(used_inputs, &(proof.used_inputs), 32);
    memcpy(data, &(proof.data), 8224);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_verify(const size_t *n_inputs, const unsigned char *used_inputs, const unsigned char *data, const unsigned char * const *ephemeral_input_tags_data, const size_t n_ephemeral_input_tags, const unsigned char *ephemeral_output_tag_data) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_surjectionproof proof;
  memcpy(&(proof.n_inputs), n_inputs, sizeof(proof.n_inputs));
  memcpy(&(proof.used_inputs), used_inputs, 32);
  memcpy(&(proof.data), data, 8224);
  secp256k1_generator ephimeral_input_tags[n_ephemeral_input_tags];
  for (int i = 0; i < (int)n_ephemeral_input_tags; ++i) {
    memcpy(&(ephimeral_input_tags[i].data), ephemeral_input_tags_data[i], 64);
  }
  secp256k1_generator ephimeral_output_tag;
  memcpy(&(ephimeral_output_tag.data), ephemeral_output_tag_data, 64);
  int ret = secp256k1_surjectionproof_verify(ctx, &proof, ephimeral_input_tags, n_ephemeral_input_tags, &ephimeral_output_tag);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_negate(unsigned char *key) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_negate(ctx, key);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_tweak_add(unsigned char *key, const unsigned char *tweak) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_tweak_add(ctx, key, tweak);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_tweak_mul(unsigned char *key, const unsigned char *tweak) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_tweak_mul(ctx, key, tweak);
  secp256k1_context_destroy(ctx);
  return ret;
}
