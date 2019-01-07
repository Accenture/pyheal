#!/usr/bin/env python
"""
Homomorphic encryption wrapper

This may eventually provide a switching layer between underlying homomorphic encryption libraries.
Note this currently does not perform comprehensive checking for validity.
"""

try:
    import seal_wrapper as seal
except ModuleNotFoundError:
    import pyheal.he_wrappers.seal_wrapper as seal

from abc import ABCMeta, abstractmethod


class BigUInt(seal.BigUInt):
    pass


class VectorUInt64(seal.VectorUInt64):
    """
    This class must be used when working with functions which return data
    by writing to a given std::vector<> (destination).
    """
    pass


class VectorInt64(seal.VectorInt64):
    """
    This class must be used when working with functions which return data
    by writing to a given std::vector<> (destination).
    """
    pass


class VectorDouble(seal.VectorDouble):
    """
    This class must be used when working with functions which return data
    by writing to a given std::vector<> (destination).
    """
    pass


class VectorComplexDouble(seal.VectorComplexDouble):
    """
    This class must be used when working with functions which return data
    by writing to a given std::vector<> (destination).
    """
    pass


class MemoryPoolHandle(seal.MemoryPoolHandle):
    def __init__(self, pool=None):
        """
        Returns a MemoryPoolHandle to a shared memory pool used by the underlying HE library.
        :param pool: Memory pool (default: None, creating a new memory pool)
        :return: MemoryPoolHandle
        """
        if pool is not None:
            super().__init__(pool)
            return

        super().__init__()


class BatchEncoder:
    def __init__(self, ctx):
        """
        Creates a BatchEncoder. It is necessary that the encryption parameters
        given through the Context object support batching.

        :param ctx: Encryption context
        :return: BatchEncoder
        """
        self.inner = seal.BatchEncoder(ctx)

    def encode(self, value, inplace=False, pool=None):
        """
        Batch encode given plaintext.
        :param value: value array
        :param inplace: Set to true to operate on the first input variable. (Default: False).
        :param pool: Memory pool. If memory pool is specified, destination is NOT used. (Default: None, uses default).
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        destination = Plaintext()
        if inplace:
            if isinstance(value, Plaintext):
                self.inner.encode(value, destination)
                return destination
            else:
                raise ValueError("Unable to perform operation in place due to different types")

        self.inner.encode(value, destination)
        return destination

    def decode(self, value, pool=None):
        """
        Batch decode given plaintext.
        :param value: Plaintext input.
        :param pool: Memory pool. If memory pool is specified, destination is NOT used. (Default: None, uses default).
        :return: Decoded values
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()
        destination = VectorUInt64()
        self.inner.decode(value, destination, pool)
        return destination

    def slot_count(self):
        """
        Returns the number of "slots" available in the batch decoder.
        :return: slot_count
        """
        return self.inner.slot_count()


class Ciphertext(seal.Ciphertext):
    def __init__(self, ctx=None, parms_id=None, size_capacity=None, pool=None):
        """
        Creates a Ciphertext container allocating no memory
        :param pool: Memory pool handle (Default: default memory handle)
        :return: Ciphertext
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if ctx is not None and parms_id is not None and size_capacity is not None:
            super().__init__(ctx, parms_id, size_capacity, pool)
            return

        if ctx is not None and parms_id is not None:
            super().__init__(ctx, parms_id, pool)
            return

        if ctx is not None:
            super().__init__(ctx, pool)
            return

        super().__init__(pool)

    def is_valid_for(self, ctx, *args, **kwargs):
        """
        Checks if Ciphertext is valid for given context.
        :return: False if invalid, True otherwise.
        """
        return super().is_valid_for(ctx)

    def python_save(self, path):
        """
        Save to output path
        :param path: File path
        :return: None
        """
        super().python_save(path)

    def python_load(self, path):
        """
        Load from path
        :param path: File path
        :return: None
        """
        super().python_load(path)

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()

    def scale(self):
        """
        Get the object's scale value
        :return: Scale (float)
        """
        return super().scale()


class CKKSEncoder:
    def __init__(self, ctx):
        """
        Provides functionality for encoding vectors of complex or real numbers into plaintext
        polynomials to be encrypted and computed on using the CKKS scheme.
        :param ctx: Encryption context
        :return: CKKSEncoder
        """
        self.inner = seal.CKKSEncoder(ctx)

    def encode(self, value, parms_id=None, scale=None, pool=None):
        """
        Encodes a value into a plaintext polynomial.
        :param value: Value for encoding.
        :param parms_id: Parameters ID for encryption (Default: None, use context from encoder)
        :param scale: Scaling parameter defining encoding precision (Default: None, not scaled)
        :param pool: Memory pool handle (Default: default memory handle)
        :return: Encoded Plaintext
        """
        destination = Plaintext()

        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if value is not None and parms_id and scale is not None:
            self.inner.encode(value, parms_id, scale, destination, pool)

        elif value is not None and scale is not None:
            self.inner.encode(value, scale, destination, pool)

        elif value is not None and parms_id is not None:
            self.inner.encode(value, parms_id, destination)

        elif value is not None:
            self.inner.encode(value, destination)

        else:
            raise ValueError("Invalid encoder parameters or combination.")

        return destination

    def decode(self, plain, inplace=False, pool=None):
        """
        Decode plaintext into value.
        :param plain: Plaintext
        :param inplace: Set to true to operate on the first input variable. (Default: False).
        :param pool: Memory pool handle (Default: default memory handle)
        :return: Decoded VectorDouble
        """
        if inplace:
            raise ValueError("Unable to perform operation in place due to different types")

        # FIXME this forces a type on the user.
        destination = VectorDouble()

        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        self.inner.decode(plain, destination, pool)

        return destination

    def slot_count(self):
        """
        Returns the number of "slots" available in the CKKS decoder.
        :return: slot_count
        """
        return self.inner.slot_count()


class EncryptionParameterQualifiers(seal.EncryptionParameterQualifiers):
    def __init__(self):
        """
        Stores a set of attributes (qualifiers) of a set of encryption parameters.
        """
        super().__init__()


class Context:
    def __init__(self, parms, expand_mod_chain=True):
        """
        Creates an encryption context with given encryption parameters.
        :param parms: EncryptionParameters
        :param expand_mod_chain: Determines whether the modulus switching chain should be created (Default: True)
        :return: Encryption context
        """
        self.context = seal.SEALContext.create(parms, expand_mod_chain)

    def parameters_set(self):
        """
        Check if the context parameters have been set correctly
        :return: True if correct, false otherwise.
        """
        return self.context.parameters_set()

    def total_coeff_modulus_bit_count(self):
        """
        Obtain the total coefficient modulus bit count
        :return: Total bit count
        """
        return self.context.total_coeff_modulus_bit_count()


class Decryptor:
    def __init__(self, ctx, secret):
        """
        Creates a Decryptor instance initialized with the specified Context and secret key.
        :param ctx: Encryption context
        :param secret: Secret key
        """
        self.inner = seal.Decryptor(ctx, secret)

    def decrypt(self, encrypted):
        """
        Decrypts a Ciphertext and stores the result in the destination parameter.

        :param encrypted: Ciphertext encrypted input
        :return: Plaintext
        """
        destination = Plaintext()
        self.inner.decrypt(encrypted, destination)
        return destination

    def invariant_noise_budget(self, encrypted):
        """
        Computes the invariant noise budget (in bits) of a ciphertext. The invariant
        noise budget measures the amount of room there is for the noise to grow while
        ensuring correct decryptions. This function works only with the BFV scheme.

        :param encrypted: Ciphertext
        :return: Integer
        """
        return self.inner.invariant_noise_budget(encrypted)


class AbstractIntegerEncoder(object, metaclass=ABCMeta):
    @abstractmethod
    def __init__(self):
        self.inner = None

    def encode(self, value):
        """
        Encodes a value to a plaintext polynomial
        :param value: Input value
        :return: Plaintext containing output.
        """
        return Plaintext(self.inner.encode(value))

    def decode(self, plain):
        """
        Default decoding as uint64
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.decode_uint64(plain)

    def decode_uint32(self, plain):
        """
        Decodes a value to a plaintext polynomial.
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.inner.decode_uint32(plain)

    def decode_uint64(self, plain):
        """
        Decodes a value to a plaintext polynomial.
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.inner.decode_uint64(plain)

    def decode_int32(self, plain):
        """
        Decodes a value to a plaintext polynomial.
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.inner.decode_int32(plain)

    def decode_int64(self, plain):
        """
        Decodes a value to a plaintext polynomial.
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.inner.decode_int64(plain)

    def decode_biguint(self, plain):
        """
        Decodes a value to a plaintext polynomial.
        :param plain: Plaintext to be decoded
        :return: Decoded value
        """
        return self.inner.decode_biguint(plain)


class BinaryEncoder(AbstractIntegerEncoder):
    def __init__(self, smallmod):
        """
        Creates a BinaryEncoder
        :param smallmod: The plaintext modulus (represented by SmallModulus)
        """
        AbstractIntegerEncoder.__init__(self)
        self.inner = seal.BinaryEncoder(smallmod)


class BalancedEncoder(AbstractIntegerEncoder):
    def __init__(self, smallmod, base=3):
        """
        Creates a BalancedEncoder
        :param smallmod: The plaintext modulus (represented by SmallModulus)
        :param base: Encoder base
        """
        AbstractIntegerEncoder.__init__(self)
        self.inner = seal.BalancedEncoder(smallmod, base)


class AbstractFractionalEncoder(object, metaclass=ABCMeta):
    @abstractmethod
    def __init__(self):
        self.inner = None

    def encode(self, value):
        """
        Encodes a double precision floating point number into a plaintext polynomial.
        :param value: Double to be encoded
        :return: Plaintext
        """
        return Plaintext(self.inner.encode(value))

    def decode(self, plain):
        """
        Decodes a plaintext polynomial and returns the result as a double-precision floating-point number.
        :param plain: Plaintext for decoding
        :return: Double
        """
        return self.inner.decode(plain)


class BinaryFractionalEncoder(AbstractFractionalEncoder):
    def __init__(self, smallmod, poly_modulus_degree, integer_coeff_count, fraction_coeff_count, base=3):
        """
        Creates a new BinaryFractionalEncoder object.
        :param smallmod: SmallModulus (plaintext)
        :param poly_modulus_degree: The degree of the polynomial modulus
        :param integer_coeff_count: The number of polynomial coefficients reserved for the integral part
        :param fraction_coeff_count: The number of polynomial coefficients reserved for the fractional part
        :return: BinaryFractionalEncoder
        """
        AbstractFractionalEncoder.__init__(self)
        self.inner = seal.BinaryFractionalEncoder(smallmod, poly_modulus_degree, integer_coeff_count,
                                                  fraction_coeff_count, base)


class BalancedFractionalEncoder(AbstractFractionalEncoder):
    def __init__(self, smallmod, poly_modulus_degree, integer_coeff_count, fraction_coeff_count, base=3):
        """
        Creates a new BalancedFractionalEncoder.
        :param smallmod: SmallModulus (plaintext)
        :param poly_modulus_degree: The degree of the polynomial modulus
        :param integer_coeff_count: The number of polynomial coefficients reserved for the integral part
        :param fraction_coeff_count: The number of polynomial coefficients reserved for the fractional part
        :param base: The base to be used for encoding (default: 3)
        """
        AbstractFractionalEncoder.__init__(self)
        self.inner = seal.BalancedFractionalEncoder(smallmod,
                                                    poly_modulus_degree,
                                                    integer_coeff_count,
                                                    fraction_coeff_count,
                                                    base)


class IntegerEncoder(AbstractIntegerEncoder):
    def __init__(self, smallmod, base=2):
        """
        Creates an IntegerEncoder.
        :param smallmod: The plaintext modulus (represented by SmallModulus)
        :param base: The base to be used for encoding (default: 2)
        """
        AbstractIntegerEncoder.__init__(self)
        self.inner = seal.IntegerEncoder(smallmod, base)


class FractionalEncoder(AbstractFractionalEncoder):
    def __init__(self, smallmod, poly_modulus_degree, integer_coeff_count, fraction_coeff_count, base=2):
        """
        Creates a new FractionalEncoder
        :param smallmod: SmallModulus (plaintext)
        :param poly_modulus_degree:  The degree of the polynomial modulus
        :param integer_coeff_count: The number of polynomial coefficients reserved for the integral part
        :param fraction_coeff_count: The number of polynomial coefficients reserved for the fractional part
        :param base: Base used for encoding (default: 2)
        :return: FractionalEncoder
        """
        AbstractFractionalEncoder.__init__(self)
        self.inner = seal.FractionalEncoder(smallmod,
                                            poly_modulus_degree,
                                            integer_coeff_count,
                                            fraction_coeff_count,
                                            base)


class EncryptionParameters(seal.EncryptionParameters):
    def __init__(self, scheme_type=None):
        """
        Creates encryption parameters based on a given scheme type
        :param scheme_type: None, BFV or CKKS
        :return: EncryptionParameters
        """
        if scheme_type is None:
            super().__init__()
            return

        if scheme_type is "BFV":
            scheme = seal.scheme_type.BFV
        elif scheme_type is "CKKS":
            scheme = seal.scheme_type.CKKS
        else:
            raise ValueError("Invalid scheme")

        super().__init__(scheme)

    def set_poly_modulus(self, size):
        """
        Sets the degree of the polynomial modulus parameter to the specified value.
        :param size: New polynomial modulus degree, must be a power of 2 (e.g.  1024, 2048, 4096, 8192, 16384, or 32768)
        :return: None
        """
        super().set_poly_modulus(size)

    def poly_modulus(self):
        """
        Get the poly modulus degree
        :return: poly_modulus_degree
        """
        return super().poly_modulus_degree()

    def set_noise_standard_deviation(self, noise_standard_deviation):
        """
        Sets the standard deviation of the noise distribution used for error sampling.
        This parameter directly affects the security level of the scheme.
        :param noise_standard_deviation: The new standard deviation
        :return: None
        """
        super().set_noise_standard_deviation(noise_standard_deviation)

    def set_plain_modulus(self, plainmodulus):
        """
        Sets the plaintext modulus parameter.
        :param plainmodulus: Integer or SmallModulus
        :return: None
        """
        super().set_plain_modulus(plainmodulus)

    def plain_modulus(self):
        """
        Get the current plain modulus
        :return: plain_modulus
        """
        return super().plain_modulus()

    def set_coeff_modulus(self, coeff_modulus, *args, **kwargs):
        """
        Sets the coefficient modulus parameter.
        :param coeff_modulus: Array of new coefficient modulus
        :return: None
        """
        super().set_coeff_modulus(coeff_modulus)

    def coeff_modulus(self):
        """
        Get the current coeff_modulus
        :return: Coeff_modulus
        """
        return super().coeff_modulus()

    def set_random_generator(self, random_generator, *args, **kwargs):
        """
        Sets the random number generator factory to use for encryption.
        By default without calling this function the default factory is used.
        :param random_generator: Random number generator factory.
        :return: None
        """
        super().set_random_generator(random_generator)

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()


class Encryptor:
    def __init__(self, ctx, public):
        """
        Creates an encryptor instance initalised with given context and public key
        :param ctx: Encryption context
        :param public: public key
        :return: Encryptor
        """
        self.inner = seal.Encryptor(ctx, public)

    def encrypt(self, plain, pool=None):
        """
        Encrypts a Plaintext and stores the result in the destination parameter.
        :param plain: The plaintext to encrypt
        :param pool: The memory pool handler (Default: None)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        destination = Ciphertext()
        self.inner.encrypt(plain, destination, pool)
        return destination


class Evaluator:
    def __init__(self, ctx):
        """
        Creates an Evaluator initialised for an encryption context
        :param ctx: Encryption context
        """
        self.inner = seal.Evaluator(ctx)

    def negate(self, encrypted, inplace=False):
        """
        Negate a value
        :param encrypted: Encrypted value to negate. Destination if destination is not set.
        :param inplace: Perform operation in place of first variable (Default: False)
        :return: negated encrypted value
        """
        if inplace:
            self.inner.negate(encrypted)
            return encrypted
        else:
            destination = Ciphertext()
            self.inner.negate(encrypted, destination)
            return destination

    def add(self, encrypted1, encrypted2, inplace=False):
        """
        Adds two encrypted values together.
        :param encrypted1: Encrypted value to add. Destination if destination is not set.
        :param encrypted2: Encrypted value to add.
        :param inplace: Perform operation in place of first variable (Default: False)
        :return: None
        """
        if inplace:
            self.inner.add(encrypted1, encrypted2)
            return encrypted1

        destination = Ciphertext()
        self.inner.add(encrypted1, encrypted2, destination)
        return destination

    def add_many(self, encrypted):
        """
        Add many encrypted and output to destination
        :param encrypted: Array of input Ciphertext
        :return: None
        """
        destination = Ciphertext()
        self.inner.add_many(encrypted, destination)
        return destination

    def sub(self, encrypted1, encrypted2, inplace=False):
        """
        Subtract one encrypted value from another.
        :param encrypted1: Encrypted value to subtract from. Destination if destination is not set.
        :param encrypted2: Encrypted value to subtract.
        :param inplace: Perform operation in place of first variable (Default: False)
        :return: None
        """
        if inplace:
            self.inner.sub(encrypted1, encrypted2)
            return encrypted1

        destination = Ciphertext()
        self.inner.sub(encrypted1, encrypted2, destination)
        return destination

    def multiply(self, encrypted1, encrypted2, inplace=False, pool=None):
        """
        Multiply encrypted values together.
        :param encrypted1: Encrypted value to multiply. Destination if destination is not set.
        :param encrypted2: Encrypted value to multiply.
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle.
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.multiply(encrypted1, encrypted2, pool)
            return encrypted1

        destination = Ciphertext()
        self.inner.multiply(encrypted1, encrypted2, destination, pool)
        return destination

    def square(self, encrypted, inplace=False, pool=None):
        """
        Squares a Ciphertext
        :param encrypted: input Ciphertext. Destination if destination is not set.
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.square(encrypted, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.square(encrypted, destination, pool)
        return destination

    def add_plain(self, encrypted, plain, inplace=False):
        """
        Add a Ciphertext and a plaintext.
        :param encrypted: Encrypted ciphertext to add. Destination if destination is not set.
        :param plain: Plaintext to add.
        :param inplace: Perform operation in place of first variable (Default: False)
        :return: None
        """
        if inplace:
            self.inner.add_plain(encrypted, plain)
            return encrypted

        destination = Ciphertext()
        self.inner.add_plain(encrypted, plain, destination)
        return destination

    def sub_plain(self, encrypted, plain, inplace=False):
        """
        Subtract a Ciphertext and a plaintext.
        :param encrypted: Encrypted ciphertext to subtract. Destination if destination is not set.
        :param plain: Plaintext to subtract.
        :param inplace: Perform operation in place of first variable (Default: False)
        :return: None
        """
        if inplace:
            self.inner.sub_plain(encrypted, plain)
            return encrypted

        destination = Ciphertext()
        self.inner.sub_plain(encrypted, plain, destination)
        return destination

    def multiply_plain(self, encrypted, plain, inplace=False, pool=None):
        """
        Multiplies a Ciphertext with a plaintext
        :param encrypted: Encrypted Ciphertext. Destination if destination is not set.
        :param plain: Plaintext to be multiplied.
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.multiply_plain(encrypted, plain, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.multiply_plain(encrypted, plain, destination, pool)
        return destination

    def multiply_many(self, encrypteds, relin_keys, pool=None):
        """
        Multiply several Ciphertexts together.
        :param encrypteds: Array of Ciphertexts
        :param relin_keys: Relinarization keys
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        destination = Ciphertext()
        self.inner.multiply_many(encrypteds, relin_keys, destination, pool)
        return destination

    def exponentiate(self, encrypted, exponent, relin_keys, inplace=False, pool=None):
        """
        Exponentiates an encrypted text.
        :param encrypted: Ciphertext to exponentiate. Destination if destination is not set.
        :param exponent: Power to raise the Ciphertext to.
        :param relin_keys: Relinarization key.
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.exponentiate(encrypted, exponent, relin_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.exponentiate(encrypted, exponent, relin_keys, destination, pool)
        return destination

    def relinearize(self, encrypted, relin_keys, inplace=False, pool=None):
        """
        Relinearizes a Ciphertext. This functions relinearizes encrypted, reducing
        its size down to 2, and stores the result in the destination parameter.
        :param encrypted: The ciphertext to relinearize. Destination if destination is not set.
        :param relin_keys: The relinearization keys
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.relinearize(encrypted, relin_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.relinearize(encrypted, relin_keys, destination, pool)
        return destination

    def rotate_rows(self, encrypted, steps, galois_keys, inplace=False, pool=None):
        """
        Rotates plaintext matrix rows cyclically (BFV scheme only)
        :param encrypted: Ciphertext to rotate. Destination if destination is not set.
        :param steps: The number of steps to rotate (negative left, positive right)
        :param galois_keys: The Galois keys
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.rotate_rows(encrypted, steps, galois_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.rotate_rows(encrypted, steps, galois_keys, destination, pool)
        return destination

    def rotate_columns(self, encrypted, galois_keys, inplace=False, pool=None):
        """
        Rotates plaintext matrix rows cyclically (BFV scheme only)
        :param encrypted: Ciphertext to rotate. Destination if destination is not set.
        :param galois_keys: The Galois keys
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.rotate_columns(encrypted, galois_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.rotate_columns(encrypted, galois_keys, destination, pool)
        return destination

    def rotate_vector(self, encrypted, steps, galois_keys, inplace=False, pool=None):
        """
        Rotates plaintext vector (CKKS scheme only)
        :param encrypted: Ciphertext to rotate. Destination if destination is not set.
        :param steps: The number of steps to rotate (negative left, positive right)
        :param galois_keys: The Galois keys
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.rotate_vector(encrypted, steps, galois_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.rotate_vector(encrypted, steps, galois_keys, destination, pool)
        return destination

    def complex_conjugate(self, encrypted, galois_keys, inplace=False, pool=None):
        """
        Complex conjugates plaintext slot values. (CKKS scheme only)
        :param encrypted: Ciphertext to rotate. Destination if destination is not set.
        :param galois_keys: The Galois keys
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.complex_conjugate(encrypted, galois_keys, pool)
            return encrypted

        destination = Ciphertext()
        self.inner.complex_conjugate(encrypted, galois_keys, destination, pool)
        return destination

    def mod_switch_to_next(self, current, inplace=False, pool=None):
        """
        Switch to next modulus in the chain.
        :param current: Current value (Plaintext or Ciphertext)
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            if isinstance(current, Ciphertext):
                self.inner.mod_switch_to_next(current, pool)
            elif isinstance(current, Plaintext):
                self.inner.mod_switch_to_next(current)
            return current

        if isinstance(current, Plaintext):
            destination = Plaintext()
            self.inner.mod_switch_to_next(current, destination)
        elif isinstance(current, Ciphertext):
            destination = Ciphertext()
            self.inner.mod_switch_to_next(current, destination, pool)
        else:
            raise ValueError("Invalid input type")

        return destination

    def mod_switch_to(self, current, parms_id, inplace=False, pool=None):
        """
        Mod switch to a given parms_id
        :param current: Current value (Plaintext or Ciphertext)
        :param parms_id: parms id to switch to
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            if isinstance(current, Ciphertext):
                self.inner.mod_switch_to(current, parms_id, pool)
            elif isinstance(current, Plaintext):
                self.inner.mod_switch_to(current, parms_id)
            return current

        if isinstance(current, Plaintext):
            destination = Plaintext()
            self.inner.mod_switch_to(current, parms_id, destination)
        elif isinstance(current, Ciphertext):
            destination = Ciphertext()
            self.inner.mod_switch_to(current, parms_id, destination, pool)
        else:
            raise ValueError("Invalid input type")

        return destination

    def rescale_to_next(self, current, inplace=False, pool=None):
        """
        Switch down modulus and scales message down accordingly.
        :param current: Current value (Ciphertext)
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.rescale_to_next(current, pool)
            return current

        destination = Ciphertext()
        self.inner.rescale_to_next(current, destination, pool)
        return destination

    def rescale_to(self, current, parms_id, inplace=False, pool=None):
        """
        Rescale to a given parms_id
        :param current: Current value (Ciphertext)
        :param parms_id: parameter ID to switch and rescale to
        :param inplace: Perform operation in place of first variable (Default: False)
        :param pool: Memory pool handle (Default: None, use default pool)
        :return: None
        """
        if pool is None:
            pool = MemoryPoolHandle().GetPool()

        if inplace:
            self.inner.rescale_to(current, parms_id, pool)
            return current

        destination = Ciphertext()
        self.inner.rescale_to(current, parms_id, destination, pool)
        return destination


class GaloisKeys(seal.GaloisKeys):
    def __init__(self, keys=None):
        if keys is not None:
            super().__init__(keys)
            return
        super().__init__()

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()


class KeyGenerator:
    def __init__(self, ctx, secret=None, public=None):
        """
        Create a Key Generator.
        :param ctx: Encryption context
        :param secret: Pre-generated secret key (Default: None)
        :param public: Pre-generated public key (Default: None)
        """
        if secret is not None and public is not None:
            self.inner = seal.KeyGenerator(ctx, secret, public)
            return

        if secret is not None:
            self.inner = seal.KeyGenerator(ctx, secret)
            return

        self.inner = seal.KeyGenerator(ctx)

    def relin_keys(self, decomposition_bit_count, count=1):
        """
        Generate relinearization keys
        :param decomposition_bit_count: The decomposition bit count [0,60]
        :param count: The number of relinearization keys to generate
        :return: RelinKeys
        """
        return self.inner.relin_keys(decomposition_bit_count, count)

    def galois_keys(self, decomposition_bit_count, vector=None):
        """
        Generates and returns Galois keys.
        :param decomposition_bit_count: The decomposition bit count [0,60]
        :param vector: The Galois elements for which to generate keys or the number of steps
        :return:
        """
        if vector is not None:
            return self.inner.galois_keys(decomposition_bit_count, vector)
        return self.inner.galois_keys(decomposition_bit_count)

    def public_key(self):
        """
        Returns a reference to the public key
        :return: PublicKey
        """
        return PublicKey(self.inner.public_key())

    def secret_key(self):
        """
        Returns a reference to the secret key
        :return: SecretKey
        """
        return SecretKey(self.inner.secret_key())


class Plaintext(seal.Plaintext):
    def __init__(self, plain=None, hex_poly=None, coeff_count=None, capacity=None):
        """
        Create a Plaintext.
        :param plain: Plaintext object (Default: None)
        :param capacity: (Default: None)
        :param coeff_count: (Default: None)
        :param hex_poly: (Default: None)
        """
        if isinstance(hex_poly, str):
            super().__init__(hex_poly)
            return

        if isinstance(plain, seal.Plaintext):
            super().__init__(plain)
            return

        if coeff_count is not None and capacity is not None:
            super().__init__(capacity, coeff_count)
            return

        if coeff_count is not None:
            super().__init__(coeff_count)
            return

        super().__init__()

    def is_zero(self):
        """
        Checks if a plaintext is zero
        :return: Boolean
        """
        return super().is_zero()

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()

    def scale(self):
        """
        Get the object's scale value
        :return: Scale (float)
        """
        return super().scale()


class PublicKey(seal.PublicKey):
    def __init__(self, key=None):
        """
        Create a public key.
        :param key: If specified, copies public key. (Default: None)
        """
        if key is not None:
            super().__init__(key)
            return
        super().__init__()

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()


class FastPRNG(seal.FastPRNG):
    def __init__(self, low_seed, high_seed):
        """
        Creates a new FastPRNG instance
        :param low_seed: Low side seed
        :param high_seed: High side seed
        """
        super().__init__(low_seed, high_seed)


class FastPRNGFactory(seal.FastPRNGFactory):
    def __init__(self, low_seed=None, high_seed=None):
        """
        Creates a new FastPRNGFactory instance.
        Note FastPRNGs should be created directly in Python if required as FastPRNGFactory::create has
        memory allocation management requirements.

        :param low_seed: Low side seed
        :param high_seed: High side seed
        """
        if low_seed is not None and high_seed is not None:
            super().__init__(low_seed, high_seed)
            return

        super().__init__(0, 0)


class RelinKey(seal.RelinKeys):
    def __init__(self, key=None):
        """
        Create a relinearization key.
        :param key: If specified, copies relinearization key. (Default: None)
        """
        if key is not None:
            super().__init__(key)
            return
        super().__init__()

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()


class SecretKey(seal.SecretKey):
    def __init__(self, key=None):
        """
        Create a secret key.
        :param key: If specified, copies secret key. (Default: None)
        """
        if key is not None:
            super().__init__(key)
            return
        super().__init__()

    def parms_id(self):
        """
        Get the object's parms_id
        :return: parms_id Array of uint64
        """
        return super().parms_id()


class SmallModulus(seal.SmallModulus):
    def __init__(self, value):
        """
        Represent an integer modulus of up to 62 bits.
        """
        if value is not None:
            super().__init__(value)
            return
        super().__init__()

    def is_zero(self):
        """
        Checks if a SmallModulus is zero
        :return: Boolean
        """
        return super().is_zero()


def coeff_modulus_128(poly_modulus_degree):
    """
    Returns the default coefficients modulus for a given polynomial modulus degree.
    :param poly_modulus_degree: Polynomial modulus degree (1024, 2048, 4096, 8192, 16384, or 32768)
    :return:
    """
    return seal.coeff_modulus_128(poly_modulus_degree)


def coeff_modulus_192(poly_modulus_degree):
    """
    Returns the default coefficients modulus for a given polynomial modulus degree.
    :param poly_modulus_degree: Polynomial modulus degree (1024, 2048, 4096, 8192, 16384, or 32768)
    :return:
    """
    return seal.coeff_modulus_128(poly_modulus_degree)


def coeff_modulus_256(poly_modulus_degree):
    """
    Returns the default coefficients modulus for a given polynomial modulus degree.
    :param poly_modulus_degree: Polynomial modulus degree (1024, 2048, 4096, 8192, 16384, or 32768)
    :return:
    """
    return seal.coeff_modulus_256(poly_modulus_degree)


def small_mods_60bit(index):
    """
    Returns a 60-bit coefficient modulus prime.
    :param index: The list index of the prime [0, 64)
    :return:
    """
    return seal.small_mods_60bit(index)


def small_mods_50bit(index):
    """
    Returns a 50-bit coefficient modulus prime.
    :param index: The list index of the prime [0, 64)
    :return:
    """
    return seal.small_mods_50bit(index)


def small_mods_40bit(index):
    """
    Returns a 40-bit coefficient modulus prime.
    :param index: The list index of the prime [0, 64)
    :return:
    """
    return seal.small_mods_40bit(index)


def small_mods_30bit(index):
    """
    Returns a 30-bit coefficient modulus prime.
    :param index: The list index of the prime [0, 64)
    :return:
    """
    return seal.small_mods_30bit(index)


def dbc_max():
    """
    Returns the maximum allowed decomposition bit count.
    :return: integer for DBC max count
    """
    return seal.dbc_max()


def dbc_min():
    """
    Returns the minimum allowed decomposition bit count.
    :return: integer for DBC min count
    """
    return seal.dbc_min()
