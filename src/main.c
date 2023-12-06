#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_musig.h"
#include "secp256k1_generator.h"
#include "secp256k1_rangeproof.h"
#include "secp256k1_preallocated.h"
#include "secp256k1_surjectionproof.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

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

int generator_generate(unsigned char *output, const unsigned char *random_seed32)
{
  secp256k1_generator gen;
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_generator_generate(ctx, &gen, random_seed32);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_generator_serialize(ctx, output, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int generator_generate_blinded(unsigned char *output, const unsigned char *key, const unsigned char *blinder)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_generator gen;
  int ret = secp256k1_generator_generate_blinded(ctx, &gen, key, blinder);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_generator_serialize(ctx, output, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_blind_generator_blind_sum(const uint64_t *values, const unsigned char *const *generator_blinds, unsigned char **blind_factors, size_t n_total, size_t n_inputs, unsigned char *bytes_out)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  blind_factors[n_total - 1] = bytes_out;
  int ret = secp256k1_pedersen_blind_generator_blind_sum(ctx, values, generator_blinds, (unsigned char *const *)blind_factors, n_total, n_inputs);
  secp256k1_context_destroy(ctx);
  return ret;
}

int pedersen_commitment(unsigned char *output, uint64_t *value, const unsigned char *generator, const unsigned char *blinder)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_generator gen;

  int ret = secp256k1_generator_parse(ctx, &gen, generator);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_pedersen_commitment commit;
  ret = secp256k1_pedersen_commit(ctx, &commit, blinder, *value, &gen);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_pedersen_commitment_serialize(ctx, output, &commit);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_sign(
    unsigned char *proof,
    size_t *plen,
    uint64_t *value,
    const unsigned char *commit_data,
    const unsigned char *generator_data,
    const unsigned char *blind,
    const unsigned char *nonce,
    int exp,
    int min_bits,
    uint64_t *min_value,
    const unsigned char *message,
    size_t msg_len,
    const unsigned char *extra_commit,
    size_t extra_commit_len)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  int ret = secp256k1_pedersen_commitment_parse(ctx, &commit, commit_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_generator gen;
  ret = secp256k1_generator_parse(ctx, &gen, generator_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_rangeproof_sign(ctx, proof, plen, *min_value, &commit, blind, nonce, exp, min_bits, *value, msg_len > 0 ? message : NULL, msg_len, extra_commit_len > 0 ? extra_commit : NULL, extra_commit_len, &gen);
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

int rangeproof_verify(uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen, const unsigned char *commit_data, const unsigned char *generator_data, const unsigned char *extra_commit, size_t extra_commit_len)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  int ret = secp256k1_pedersen_commitment_parse(ctx, &commit, commit_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_generator gen;
  ret = secp256k1_generator_parse(ctx, &gen, generator_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_rangeproof_verify(ctx, min_value, max_value, &commit, proof, plen, extra_commit, extra_commit_len, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int rangeproof_rewind(unsigned char *blind_out, uint64_t *value_out, uint64_t *min_value, uint64_t *max_value, unsigned char *message_out, size_t *outlen, const unsigned char *proof, size_t plen, const unsigned char *commit_data, const unsigned char *generator_data, const unsigned char *nonce, const unsigned char *extra_commit, size_t extra_commit_len)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pedersen_commitment commit;
  int ret = secp256k1_pedersen_commitment_parse(ctx, &commit, commit_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_generator gen;
  ret = secp256k1_generator_parse(ctx, &gen, generator_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_rangeproof_rewind(ctx, blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commit, proof, plen, extra_commit, extra_commit_len, &gen);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_initialize(unsigned char *output, size_t *outputlen, size_t *input_index, const unsigned char *const *input_tags_data, const size_t n_input_tags, const size_t n_input_tags_to_use, const unsigned char *output_tag_data, const size_t n_max_iterations, const unsigned char *random_seed32)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_fixed_asset_tag input_tags[n_input_tags];
  for (int i = 0; i < (int)n_input_tags; ++i)
  {
    memcpy(&(input_tags[i].data), input_tags_data[i], 32);
  }

  secp256k1_fixed_asset_tag output_tag;
  memcpy(&(output_tag.data), output_tag_data, 32);

  secp256k1_surjectionproof proof;
  int ret = secp256k1_surjectionproof_initialize(ctx, &proof, input_index, input_tags, n_input_tags, n_input_tags_to_use, &output_tag, n_max_iterations, random_seed32);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_surjectionproof_serialize(ctx, output, outputlen, &proof);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_generate(unsigned char *output, size_t *outputlen, const unsigned char *proof_data, const size_t proof_len, const unsigned char *const *ephemeral_input_tags_data, const size_t n_ephemeral_input_tags, const unsigned char *ephemeral_output_tag_data, size_t input_index, const unsigned char *input_blinding_key, const unsigned char *output_blinding_key)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_surjectionproof proof;
  int ret = secp256k1_surjectionproof_parse(ctx, &proof, proof_data, proof_len);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_generator ephemeral_input_tags[n_ephemeral_input_tags];
  for (int i = 0; i < (int)n_ephemeral_input_tags; ++i)
  {
    int ret = secp256k1_generator_parse(ctx, &ephemeral_input_tags[i], ephemeral_input_tags_data[i]);
    if (!ret)
    {
      secp256k1_context_destroy(ctx);
      return ret;
    }
  }
  secp256k1_generator ephemeral_output_tag;
  ret = secp256k1_generator_parse(ctx, &ephemeral_output_tag, ephemeral_output_tag_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_ephemeral_input_tags, &ephemeral_output_tag, input_index, input_blinding_key, output_blinding_key);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_surjectionproof_serialize(ctx, output, outputlen, &proof);
  secp256k1_context_destroy(ctx);
  return ret;
}

int surjectionproof_verify(const unsigned char *proof_data, const size_t proof_len, const unsigned char *const *ephemeral_input_tags_data, const size_t n_ephemeral_input_tags, const unsigned char *ephemeral_output_tag_data)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_surjectionproof proof;
  int ret = secp256k1_surjectionproof_parse(ctx, &proof, proof_data, proof_len);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  secp256k1_generator ephemeral_input_tags[n_ephemeral_input_tags];
  for (int i = 0; i < (int)n_ephemeral_input_tags; ++i)
  {
    int ret = secp256k1_generator_parse(ctx, &ephemeral_input_tags[i], ephemeral_input_tags_data[i]);
    if (!ret)
    {
      secp256k1_context_destroy(ctx);
      return ret;
    }
  }
  secp256k1_generator ephemeral_output_tag;
  ret = secp256k1_generator_parse(ctx, &ephemeral_output_tag, ephemeral_output_tag_data);
  if (!ret)
  {
    secp256k1_context_destroy(ctx);
    return ret;
  }

  ret = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_ephemeral_input_tags, &ephemeral_output_tag);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_negate(unsigned char *key)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_negate(ctx, key);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_tweak_add(unsigned char *key, const unsigned char *tweak)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_tweak_add(ctx, key, tweak);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_tweak_mul(unsigned char *key, const unsigned char *tweak)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_tweak_mul(ctx, key, tweak);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_tweak_sub(unsigned char *key, const unsigned char *tweak)
{
  unsigned char *t = malloc(32);
  memcpy(t, tweak, 32);
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  int ret = secp256k1_ec_seckey_negate(ctx, t);
  if (ret == 1)
  {
    ret = secp256k1_ec_seckey_tweak_add(ctx, key, (const unsigned char *)t);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_is_valid_xonly_pubkey(const unsigned char *key)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_xonly_pubkey pubkey;
  int ret = secp256k1_xonly_pubkey_parse(ctx, &pubkey, key);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_is_valid_pubkey(const unsigned char *key, size_t key_len)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, key, key_len);
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_is_point(const unsigned char *key, size_t key_len)
{
  if (key_len == 32)
  {
    return ec_is_valid_xonly_pubkey(key);
  }

  return ec_is_valid_pubkey(key, key_len);
}

int ec_point_compress(unsigned char *output, size_t *output_len, const unsigned char *point, size_t point_len, int compress)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, point, point_len);
  if (ret == 1)
  {
    ret = secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_point_from_scalar(unsigned char *output, size_t *output_len, const unsigned char *scalar, int compress)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, scalar);
  if (ret == 1)
  {
    ret = secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_x_only_point_tweak_add(unsigned char *output, int *parity, const unsigned char *point, const unsigned char *tweak)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_xonly_pubkey pubkey;
  secp256k1_pubkey pubkey_result;
  int ret = secp256k1_xonly_pubkey_parse(ctx, &pubkey, point);
  if (ret == 1)
  {
    ret = secp256k1_xonly_pubkey_tweak_add(ctx, &pubkey_result, &pubkey, tweak);
    if (ret == 1)
    {
      ret = secp256k1_xonly_pubkey_from_pubkey(ctx, &pubkey, parity, &pubkey_result);
      if (ret == 1)
      {
        ret = secp256k1_xonly_pubkey_serialize(ctx, output, &pubkey);
      }
    }
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_sign_ecdsa(unsigned char *output, const unsigned char *d, const unsigned char *h, int withextradata, const unsigned char *e)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_ecdsa_signature sig;
  int ret = secp256k1_ecdsa_sign(ctx, &sig, h, d, secp256k1_nonce_function_rfc6979, withextradata ? e : NULL);
  if (ret == 1)
  {
    ret = secp256k1_ecdsa_signature_serialize_compact(ctx, output, &sig);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_verify_ecdsa(const unsigned char *q, size_t q_len, const unsigned char *h, const unsigned char *sig, const int strict)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_ecdsa_signature sig_parsed;
  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, q, q_len);
  if (ret == 1)
  {
    ret = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_parsed, sig);
    if (ret == 1)
    {
      if (strict == 0)
      {
        ret = secp256k1_ecdsa_signature_normalize(ctx, &sig_parsed, &sig_parsed);
      }
      ret = secp256k1_ecdsa_verify(ctx, &sig_parsed, h, &pubkey);
    }
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_sign_schnorr(unsigned char *output, const unsigned char *d, const unsigned char *h, const int withextradata, const unsigned char *e)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_keypair key;
  int ret = secp256k1_keypair_create(ctx, &key, d);
  if (ret == 1)
  {
    ret = secp256k1_schnorrsig_sign32(ctx, output, h, &key, withextradata ? e : NULL);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_verify_schnorr(const unsigned char *q, const unsigned char *h, size_t h_len, const unsigned char *sig)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_xonly_pubkey pubkey;
  int ret = secp256k1_xonly_pubkey_parse(ctx, &pubkey, q);
  if (ret == 1)
  {
    ret = secp256k1_schnorrsig_verify(ctx, sig, h, h_len, &pubkey);
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

int ec_seckey_verify(const unsigned char *seckey)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  int ret = secp256k1_ec_seckey_verify(ctx, seckey);
  secp256k1_context_destroy(ctx);
  return ret;
}

int isZero(const unsigned char *array, size_t size)
{
  for (size_t i = 0; i < size; i++)
  {
    if (array[i] != 0)
    {
      return 0;
    }
  }
  return 1;
}

int ec_point_add_scalar(unsigned char *output, size_t *output_len, const unsigned char *point, const unsigned char *tweak, int compress)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_ALL);
  secp256k1_pubkey pubkey;
  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, point, 33);
  if (ret == 1)
  {
    // check if the tweak is zero
    if (isZero(tweak, 32) == 1)
    {
      // if so, just serialize the pubkey
      ret = secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    }
    else
    {
      // otherwise, add the tweak to the pubkey
      ret = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak);
      if (ret == 1)
      {
        ret = secp256k1_ec_pubkey_serialize(ctx, output, output_len, &pubkey, compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
      }
    }
  }
  secp256k1_context_destroy(ctx);
  return ret;
}

void **alloc_pointer_arr(size_t n, size_t elem_size)
{
  void **arr = malloc(sizeof(void *) * n);
  for (int i = 0; i < n; i++)
  {
    arr[i] = malloc(elem_size);
  }
  return arr;
}

void free_pointer_arr(void **ptrs, size_t n)
{
  for (int i = 0; i < n; i++)
  {
    free(ptrs[i]);
  }
  free(ptrs);
}

#define RETURN_ON_ZERO              \
  if (ret == 0)                     \
  {                                 \
    secp256k1_context_destroy(ctx); \
    return ret;                     \
  }

int musig_pubkey_agg(unsigned char *agg_pubkey, secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char **pubkeys, size_t n_pubkeys)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  secp256k1_xonly_pubkey **pubkeys_ptr = (secp256k1_xonly_pubkey **)alloc_pointer_arr(n_pubkeys, sizeof(secp256k1_xonly_pubkey));

  int ret = 1;
  for (int i = 0; i < n_pubkeys && ret == 1; i++)
  {
    ret = secp256k1_xonly_pubkey_parse(ctx, pubkeys_ptr[i], pubkeys[i]);
  }

  if (ret == 1)
  {
    secp256k1_xonly_pubkey agg_pubkey_temp;
    ret = secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pubkey_temp, keyagg_cache, (const secp256k1_xonly_pubkey *const *) pubkeys_ptr, n_pubkeys);

    if (ret == 1)
    {
      ret = secp256k1_xonly_pubkey_serialize(ctx, agg_pubkey, &agg_pubkey_temp);
    }
  }

  free_pointer_arr((void **)pubkeys_ptr, n_pubkeys);
  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_nonce_gen(secp256k1_musig_secnonce *secnonce, unsigned char *pubnonce, const unsigned char *session_id32)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  secp256k1_musig_pubnonce pubnonce_temp;
  int ret = secp256k1_musig_nonce_gen(ctx, secnonce, &pubnonce_temp, session_id32, NULL, NULL, NULL, NULL);
  RETURN_ON_ZERO;

  ret = secp256k1_musig_pubnonce_serialize(ctx, pubnonce, &pubnonce_temp);

  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_nonce_agg(unsigned char *aggnonce, const unsigned char *const *pubnonces, size_t n_pubnonces)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  secp256k1_musig_pubnonce **pubnonces_ptr = (secp256k1_musig_pubnonce **)alloc_pointer_arr(n_pubnonces, sizeof(secp256k1_musig_pubnonce));

  int ret = 1;
  for (int i = 0; i < n_pubnonces && ret == 1; i++)
  {
    ret = secp256k1_musig_pubnonce_parse(ctx, pubnonces_ptr[i], pubnonces[i]);
  }

  if (ret == 1)
  {
    secp256k1_musig_aggnonce aggnonce_temp;
    ret = secp256k1_musig_nonce_agg(ctx, &aggnonce_temp, (const secp256k1_musig_pubnonce *const *)pubnonces_ptr, n_pubnonces);

    if (ret == 1)
    {
      ret = secp256k1_musig_aggnonce_serialize(ctx, aggnonce, &aggnonce_temp);
    }
  }

  free_pointer_arr((void **)pubnonces_ptr, n_pubnonces);
  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_nonce_process(secp256k1_musig_session *session, const unsigned char *aggnonce_serialized, const unsigned char *msg32, const secp256k1_musig_keyagg_cache *keyagg_cache)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

  secp256k1_musig_aggnonce aggnonce;
  int ret = secp256k1_musig_aggnonce_parse(ctx, &aggnonce, aggnonce_serialized);
  RETURN_ON_ZERO;

  ret = secp256k1_musig_nonce_process(ctx, session, &aggnonce, msg32, keyagg_cache, NULL);

  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_partial_sign(unsigned char *partial_sig, secp256k1_musig_secnonce *secnonce, const unsigned char *seckey, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_musig_session *session)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  secp256k1_keypair keypair;
  int ret = secp256k1_keypair_create(ctx, &keypair, seckey);
  RETURN_ON_ZERO;

  secp256k1_musig_partial_sig sig_temp;
  ret = secp256k1_musig_partial_sign(ctx, &sig_temp, secnonce, &keypair, keyagg_cache, session);
  RETURN_ON_ZERO;

  ret = secp256k1_musig_partial_sig_serialize(ctx, partial_sig, &sig_temp);

  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_partial_sig_verify(
  const unsigned char *partial_sig,
  const unsigned char *pubnonce,
  const unsigned char *pubkey,
  const secp256k1_musig_keyagg_cache *keyagg_cache,
  const secp256k1_musig_session *session)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

  secp256k1_musig_partial_sig sig_temp;
  int ret = secp256k1_musig_partial_sig_parse(ctx, &sig_temp, partial_sig);
  RETURN_ON_ZERO;

  secp256k1_musig_pubnonce pubnonce_temp;
  ret = secp256k1_musig_pubnonce_parse(ctx, &pubnonce_temp, pubnonce);
  RETURN_ON_ZERO;

  secp256k1_xonly_pubkey pubkey_temp;
  ret = secp256k1_xonly_pubkey_parse(ctx, &pubkey_temp, pubkey);
  RETURN_ON_ZERO;

  ret = secp256k1_musig_partial_sig_verify(ctx, &sig_temp, &pubnonce_temp, &pubkey_temp, keyagg_cache, session);

  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_partial_sig_agg(
  unsigned char *sig,
  const secp256k1_musig_session *session,
  unsigned char **partial_sigs,
  size_t n_sigs)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  secp256k1_musig_partial_sig **sigs_ptr = (secp256k1_musig_partial_sig **)alloc_pointer_arr(n_sigs, sizeof(secp256k1_musig_partial_sig));

  int ret = 1;
  for (int i = 0; i < n_sigs && ret == 1; i++)
  {
    ret = secp256k1_musig_partial_sig_parse(ctx, sigs_ptr[i], partial_sigs[i]);
  }

  if (ret == 1)
  {
    ret = secp256k1_musig_partial_sig_agg(ctx, sig, session, (const secp256k1_musig_partial_sig *const *)sigs_ptr, n_sigs);
  }

  free_pointer_arr((void **)sigs_ptr, n_sigs);
  secp256k1_context_destroy(ctx);
  return ret;
}

int musig_pubkey_xonly_tweak_add(
  unsigned char *output,
  size_t *output_len,
  int compress,
  secp256k1_musig_keyagg_cache *keyagg_cache,
  const unsigned char *tweak)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

  secp256k1_pubkey output_temp;
  int ret = secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_temp, keyagg_cache, tweak);
  RETURN_ON_ZERO;

  ret = secp256k1_ec_pubkey_serialize(ctx, output, output_len, &output_temp, compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  secp256k1_context_destroy(ctx);
  return ret;
}
