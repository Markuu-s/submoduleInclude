#ifndef _SCHNORRKEL_INCLUDE_GUARD_H_
#define _SCHNORRKEL_INCLUDE_GUARD_H_

/* Generated with cbindgen:0.14.3 */

/* THIS FILE WAS AUTOMATICALLY GENERATED. DO NOT EDIT. Ref: https://github.com/soramitsu/sr25519-crust */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The length of an "expanded" ed25519 key, `ExpandedSecretKey`, in bytes.
 */
#define ED25519_EXPANDED_SECRET_KEY_LENGTH 64

/**
 * The length of an ed25519 `Keypair`, in bytes.
 */
#define ED25519_KEYPAIR_LENGTH (ED25519_PUBLIC_KEY_LENGTH + ED25519_SECRET_KEY_LENGTH)

/**
 * The length of an ed25519 `PublicKey`, in bytes.
 */
#define ED25519_PUBLIC_KEY_LENGTH 32

/**
 * The length of a ed25519 `SecretKey`, in bytes.
 */
#define ED25519_SECRET_KEY_LENGTH 32

/**
 * Length of a random generator seed
 */
#define ED25519_SEED_LENGTH 32

/**
 * The length of a ed25519 `Signature`, in bytes.
 */
#define ED25519_SIGNATURE_LENGTH 64

/**
 * Size of CHAINCODE, bytes
 */
#define SR25519_CHAINCODE_SIZE 32

/**
 * Size of SR25519 KEYPAIR. [32 bytes key | 32 bytes nonce | 32 bytes public]
 */
#define SR25519_KEYPAIR_SIZE 96

/**
 * Size of SR25519 PUBLIC KEY, bytes
 */
#define SR25519_PUBLIC_SIZE 32

/**
 * Size of SR25519 PRIVATE (SECRET) KEY, which consists of [32 bytes key | 32 bytes nonce]
 */
#define SR25519_SECRET_SIZE 64

/**
 * Size of input SEED for derivation, bytes
 */
#define SR25519_SEED_SIZE 32

/**
 * Size of SR25519 SIGNATURE, bytes
 */
#define SR25519_SIGNATURE_SIZE 64

/**
 * Size of VRF output, bytes
 */
#define SR25519_VRF_OUTPUT_SIZE 32

/**
 * Size of VRF proof, bytes
 */
#define SR25519_VRF_PROOF_SIZE 64

/**
 * Size of VRF raw output, bytes
 */
#define SR25519_VRF_RAW_OUTPUT_SIZE 16

/**
 * Size of VRF limit, bytes
 */
#define SR25519_VRF_THRESHOLD_SIZE 16

/**
 * Status code of a function call
 */
typedef enum Ed25519Result {
  /**
   * Success
   */
  ED25519_RESULT_OK = 0,
  /**
   * a pointer argument passed into function is null
   */
  ED25519_RESULT_NULL_ARGUMENT,
  /**
   * decoding a keypair from bytes failed
   */
  ED25519_RESULT_KEYPAIR_FROM_BYTES_FAILED,
  /**
   * decoding a public key from bytes failed
   */
  ED25519_RESULT_PUBLIC_KEY_FROM_BYTES_FAILED,
  /**
   * decoding a signature from bytes failed
   */
  ED25519_RESULT_SIGNATURE_FROM_BYTES_FAILED,
  /**
   * sign operation failed
   */
  ED25519_RESULT_SIGN_FAILED,
  /**
   * signature verification failed
   */
  ED25519_RESULT_VERIFICATION_FAILED,
} Ed25519Result;

/**
 * status code of a function call
 */
typedef enum Sr25519SignatureResult {
  /**
   * Success
   */
  SR25519_SIGNATURE_RESULT_OK,
  /**
   * A signature verification equation failed.
   *
   * We emphasise that all variants represent a failed signature,
   * not only this one.
   */
  SR25519_SIGNATURE_RESULT_EQUATION_FALSE,
  /**
   * Invalid point provided, usually to `verify` methods.
   */
  SR25519_SIGNATURE_RESULT_POINT_DECOMPRESSION_ERROR,
  /**
   * Invalid scalar provided, usually to `Signature::from_bytes`.
   */
  SR25519_SIGNATURE_RESULT_SCALAR_FORMAT_ERROR,
  /**
   * An error in the length of bytes handed to a constructor.
   *
   * To use this, pass a string specifying the `name` of the type
   * which is returning the error, and the `length` in bytes which
   * its constructor expects.
   */
  SR25519_SIGNATURE_RESULT_BYTES_LENGTH_ERROR,
  /**
   * Signature not marked as schnorrkel, maybe try ed25519 instead.
   */
  SR25519_SIGNATURE_RESULT_NOT_MARKED_SCHNORRKEL,
  /**
   * There is no record of the preceeding multi-signautre protocol
   * stage for the specified public key.
   */
  SR25519_SIGNATURE_RESULT_MU_SIG_ABSENT,
  /**
   * For this public key, there are either conflicting records for
   * the preceeding multi-signautre protocol stage or else duplicate
   * duplicate records for the current stage.
   */
  SR25519_SIGNATURE_RESULT_MU_SIG_INCONSISTENT,
} Sr25519SignatureResult;

/**
 * Result of a VRF
 */
typedef struct VrfResult {
  /**
   * status code
   */
  Sr25519SignatureResult result;
  /**
   * is the output of the function less than the provided threshold
   */
  bool is_less;
} VrfResult;

/**
 * This is literally a copy of Strobe128 from merlin lib
 * Have to copy it as a workaround for passing a strobe object from C code
 * Because the orignal Strobe128 structure is private and it is impossible to initialize it from
 * a ready byte array
 */
typedef struct Strobe128 {
  uint8_t state[200];
  uint8_t pos;
  uint8_t pos_begin;
  uint8_t cur_flags;
} Strobe128;

/**
 *  * Generate a keypair using the provided seed  * @arg seed_ptr - the seed that will be used as a secret key
 */
void ed25519_keypair_from_seed(uint8_t *keypair_out,
                               const uint8_t *seed_ptr);

/**
 *  * Sign the message using the provided keypair  * @returns a status code as the function return value, a signature as an output parameter
 */
Ed25519Result ed25519_sign(uint8_t *signature_out,
                           const uint8_t *keypair_ptr,
                           const uint8_t *message_ptr,
                           unsigned long message_size);

/**
 *  * Verify a signature of a message using provided public key
 */
Ed25519Result ed25519_verify(const uint8_t *signature_ptr,
                             const uint8_t *public_key_ptr,
                             const uint8_t *message_ptr,
                             unsigned long message_size);

/**
 * Perform a derivation on a secret
 *
 * * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
 * * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
 * * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
 *
 */
void sr25519_derive_keypair_hard(uint8_t *keypair_out,
                                 const uint8_t *pair_ptr,
                                 const uint8_t *cc_ptr);

/**
 * Perform a derivation on a secret
 *
 * * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
 * * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
 * * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
 *
 */
void sr25519_derive_keypair_soft(uint8_t *keypair_out,
                                 const uint8_t *pair_ptr,
                                 const uint8_t *cc_ptr);

/**
 * Perform a derivation on a publicKey
 *
 * * pubkey_out: pre-allocated output buffer of SR25519_PUBLIC_SIZE bytes
 * * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
 * * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
 *
 */
void sr25519_derive_public_soft(uint8_t *pubkey_out,
                                const uint8_t *public_ptr,
                                const uint8_t *cc_ptr);

/**
 * Generate a key pair.
 *
 * * keypair_out: keypair [32b key | 32b nonce | 32b public], pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
 * * seed: generation seed - input buffer of SR25519_SEED_SIZE bytes
 *
 */
void sr25519_keypair_from_seed(uint8_t *keypair_out,
                               const uint8_t *seed_ptr);

/**
 * Sign a message
 *
 * The combination of both public and private key must be provided.
 * This is effectively equivalent to a keypair.
 *
 * * signature_out: output buffer of ED25519_SIGNATURE_SIZE bytes
 * * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
 * * secret_ptr: private key (secret) - input buffer of SR25519_SECRET_SIZE bytes
 * * message_ptr: Arbitrary message; input buffer of size message_length
 * * message_length: Length of a message
 *
 */
void sr25519_sign(uint8_t *signature_out,
                  const uint8_t *public_ptr,
                  const uint8_t *secret_ptr,
                  const uint8_t *message_ptr,
                  unsigned long message_length);

/**
 * Verify a message and its corresponding against a public key;
 *
 * * signature_ptr: verify this signature
 * * message_ptr: Arbitrary message; input buffer of message_length bytes
 * * message_length: Message size
 * * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
 *
 * * returned true if signature is valid, false otherwise
 */
bool sr25519_verify(const uint8_t *signature_ptr,
                    const uint8_t *message_ptr,
                    unsigned long message_length,
                    const uint8_t *public_ptr);

/**
 * Verify a message and its corresponding against a public key;
 *
 * * signature_ptr: verify this signature
 * * message_ptr: Arbitrary message; input buffer of message_length bytes
 * * message_length: Message size
 * * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
 *
 * * returned true if signature is valid, false otherwise
 */
bool sr25519_verify_deprecated(const uint8_t *signature_ptr,
                               const uint8_t *message_ptr,
                               unsigned long message_length,
                               const uint8_t *public_ptr);

/**
 * Sign the provided message using a Verifiable Random Function and
 * if the result is less than \param limit provide the proof
 * @param out_and_proof_ptr pointer to output array, where the VRF out and proof will be written
 * @param keypair_ptr byte representation of the keypair that will be used during signing
 * @param message_ptr byte array to be signed
 * @param limit_ptr byte array, must be 16 bytes long
 *
 */
VrfResult sr25519_vrf_sign_if_less(uint8_t *out_and_proof_ptr,
                                   const uint8_t *keypair_ptr,
                                   const uint8_t *message_ptr,
                                   unsigned long message_length,
                                   const uint8_t *limit_ptr);

/**
 * Sign the provided transcript using a Verifiable Random Function and
 * if the result is less than \param limit provide the proof
 * @param out_and_proof_ptr - pointer to output array, where the VRF out and proof will be written
 * @param keypair_ptr - byte representation of the keypair that will be used during signing
 * @param transcript_data - pointer to a Strobe object, which is an internal representation of the transcript data
 * @param limit_ptr - byte array, must be 16 bytes long
 */
VrfResult sr25519_vrf_sign_transcript(uint8_t *out_and_proof_ptr,
                                      const uint8_t *keypair_ptr,
                                      const Strobe128 *transcript_data,
                                      const uint8_t *limit_ptr);

/**
 * Verify a signature produced by a VRF with its original input and the corresponding proof and
 * check if the result of the function is less than the threshold.
 * @note If errors, is_less field of the returned structure is not meant to contain a valid value
 * @param public_key_ptr byte representation of the public key that was used to sign the message
 * @param message_ptr the orignal signed message
 * @param output_ptr the signature
 * @param proof_ptr the proof of the signature
 * @param threshold_ptr the threshold to be compared against
 */
VrfResult sr25519_vrf_verify(const uint8_t *public_key_ptr,
                             const uint8_t *message_ptr,
                             unsigned long message_length,
                             const uint8_t *output_ptr,
                             const uint8_t *proof_ptr,
                             const uint8_t *threshold_ptr);

/**
 * Verify a signature produced by a VRF with its original input transcript and the corresponding proof and
 * check if the result of the function is less than the threshold.
 * @note If errors, is_less field of the returned structure is not meant to contain a valid value
 * @param public_key_ptr - byte representation of the public key that was used to sign the message
 * @param transcript_data - pointer to a Strobe object, which is an internal representation
 *                          of the signed transcript data
 * @param output_ptr - the signature
 * @param proof_ptr - the proof of the signature
 * @param threshold_ptr - the threshold to be compared against
 */
VrfResult sr25519_vrf_verify_transcript(const uint8_t *public_key_ptr,
                                        const Strobe128 *transcript_data,
                                        const uint8_t *output_ptr,
                                        const uint8_t *proof_ptr,
                                        const uint8_t *threshold_ptr);

#endif /* _SCHNORRKEL_INCLUDE_GUARD_H_ */
