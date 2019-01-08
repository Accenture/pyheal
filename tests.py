#!/usr/bin/env python
"""
he_wrapper.wrapper testing

To execute, install seal_wrapper standalone from he_wrappers folder:
pip install .

If using pytest:
pytest tests.py

If using Python unittest:
python -m unittest tests.py
"""
try:
    import wrapper as heal
except ModuleNotFoundError:
    import pyheal.he_wrappers.wrapper as heal
import unittest
import math


class TestBFV(unittest.TestCase):
    def test_example_bfv_1(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("BFV")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(2048)
        assert parms.poly_modulus() == 2048
        parms.set_coeff_modulus(heal.coeff_modulus_128(2048))
        assert parms.coeff_modulus()[0].bit_count() == 54
        parms.set_plain_modulus(heal.SmallModulus(1 << 8))
        assert parms.plain_modulus().value() == 256

        # Create context
        context = heal.Context(parms).context
        assert context.parameters_set()

        int_encoder = heal.IntegerEncoder(parms.plain_modulus())
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()

        encryptor = heal.Encryptor(context, public)
        decryptor = heal.Decryptor(context, secret)
        evaluator = heal.Evaluator(context)

        value1 = 5
        plain1 = int_encoder.encode(value1)
        value2 = -7
        plain2 = int_encoder.encode(value2)

        cipher1 = encryptor.encrypt(plain1)
        cipher2 = encryptor.encrypt(plain2)

        assert decryptor.invariant_noise_budget(cipher1) == 35
        assert decryptor.invariant_noise_budget(cipher1) == 35

        evaluator.negate(cipher1, inplace=True)
        assert decryptor.invariant_noise_budget(cipher1) == 35

        evaluator.add(cipher1, cipher2, inplace=True)
        assert decryptor.invariant_noise_budget(cipher1) == 51

        evaluator.multiply(cipher1, cipher2, inplace=True)
        assert decryptor.invariant_noise_budget(cipher1) == 27

        result = heal.Plaintext()
        result = decryptor.decrypt(cipher1)
        assert result.to_string() == "2x^4 + 3x^3 + 5x^2 + 3x^1 + 2"
        assert int_encoder.decode(result) == 84

    def test_example_bfv_2(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("BFV")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus(heal.coeff_modulus_128(8192))
        parms.set_plain_modulus(1 << 10)

        # Create context
        context = heal.Context(parms).context
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)

        # Original squaring example to observe decreasing noise budget and increasing size
        plain1 = heal.Plaintext(hex_poly="1x^2 + 2x^1 + 3")
        encrypted = encryptor.encrypt(plain1)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 196
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) == 173
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 5
        assert decryptor.invariant_noise_budget(encrypted) == 138
        plain2 = decryptor.decrypt(encrypted)
        assert plain2.to_string() == "1x^8 + 8x^7 + 24x^6 + 68x^5 + D6x^4 + 138x^3 + 144x^2 + D8x^1 + 51"

        # Relinearisation example, showing decomposition bit count = 16
        relin_key16 = keygen.relin_keys(16)
        encrypted = encryptor.encrypt(plain1)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 196
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) == 173
        evaluator.relinearize(encrypted, relin_key16, inplace=True)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 173
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) <= 145
        evaluator.relinearize(encrypted, relin_key16, inplace=True)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) <= 145
        plain2 = decryptor.decrypt(encrypted)
        assert plain2.to_string() == "1x^8 + 8x^7 + 24x^6 + 68x^5 + D6x^4 + 138x^3 + 144x^2 + D8x^1 + 51"

        # Relinearisation example, showing decomposition bit count = 60
        relin_key60 = keygen.relin_keys(60)
        encrypted = encryptor.encrypt(plain1)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 196
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) == 173
        evaluator.relinearize(encrypted, relin_key60, inplace=True)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 142
        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) == 115
        evaluator.relinearize(encrypted, relin_key60, inplace=True)
        assert encrypted.size() == 2
        assert decryptor.invariant_noise_budget(encrypted) == 115
        plain2 = decryptor.decrypt(encrypted)
        assert plain2.to_string() == "1x^8 + 8x^7 + 24x^6 + 68x^5 + D6x^4 + 138x^3 + 144x^2 + D8x^1 + 51"

        evaluator.square(encrypted, inplace=True)
        assert encrypted.size() == 3
        assert decryptor.invariant_noise_budget(encrypted) <= 86
        evaluator.relinearize(encrypted, relin_key60, inplace=True)
        plain2 = decryptor.decrypt(encrypted)
        assert plain2.to_string() == "1x^16 + 10x^15 + 88x^14 + 310x^13 + 13Cx^12 + 110x^11 + 78x^10 " + \
               "+ 390x^9 + 1A6x^8 + 2B0x^7 + 38x^6 + B0x^5 + 3FCx^4 + 30x^3 + 348x^2 + B0x^1 + 1A1"

    def test_example_bfv_3(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("BFV")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(4096)
        parms.set_coeff_modulus(heal.coeff_modulus_128(4096))
        parms.set_plain_modulus(40961)  # Prime number and 2 * 4096 divides 40960, auto enabled batching

        # Create context
        context = heal.Context(parms).context
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()

        gal_keys = keygen.galois_keys(30)
        relin_keys = keygen.relin_keys(30)

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)

        # Sample demonstrating batch encoding
        batch_encoder = heal.BatchEncoder(context)
        slot_count = batch_encoder.slot_count()
        row_size = slot_count / 2
        assert slot_count == 4096
        assert row_size == 2048.0

        # Build matrix
        pod_matrix = heal.VectorUInt64()
        for i in range(0, slot_count):
            pod_matrix.append(0)
        pod_matrix[0] = 0
        pod_matrix[1] = 1
        pod_matrix[2] = 2
        pod_matrix[3] = 3
        pod_matrix[int(row_size)] = 4
        pod_matrix[int(row_size) + 1] = 5
        pod_matrix[int(row_size) + 2] = 6
        pod_matrix[int(row_size) + 3] = 7

        # Test batch operations
        plain_matrix = batch_encoder.encode(pod_matrix)

        encrypted_matrix = encryptor.encrypt(plain_matrix)
        assert decryptor.invariant_noise_budget(encrypted_matrix) == 82

        pod_matrix2 = []
        for i in range(0, slot_count):
            pod_matrix2.append((i % 2) + 1)
        plain_matrix2 = heal.Plaintext(pod_matrix2)
        evaluator.add_plain(encrypted_matrix, plain_matrix2, inplace=True)
        evaluator.square(encrypted_matrix, inplace=True)
        evaluator.relinearize(encrypted_matrix, relin_keys, inplace=True)
        assert decryptor.invariant_noise_budget(encrypted_matrix) <= 54

        plain_result = decryptor.decrypt(encrypted_matrix)
        pod_result = batch_encoder.decode(value=plain_result)
        assert pod_result[1] == 1
        assert pod_result[2] == 4
        assert pod_result[3] == 9

        # Rotate matrix 3 steps left
        encrypted_matrix = encryptor.encrypt(plain_matrix)
        evaluator.rotate_rows(encrypted_matrix, 3, gal_keys, inplace=True)
        plain_result = decryptor.decrypt(encrypted_matrix)
        pod_result = batch_encoder.decode(plain_result)
        assert pod_result[0] == 3
        assert pod_result[1] == 0
        assert decryptor.invariant_noise_budget(encrypted_matrix) == 53

        # Swap rows (rotate columns)
        evaluator.rotate_columns(encrypted_matrix, gal_keys, inplace=True)
        plain_result = decryptor.decrypt(encrypted_matrix)
        pod_result = batch_encoder.decode(plain_result)
        assert pod_result[0] == 7
        assert pod_result[1] == 0
        assert decryptor.invariant_noise_budget(encrypted_matrix) == 53

        # Rotate matrix 4 steps right
        evaluator.rotate_rows(encrypted_matrix, -4, gal_keys, inplace=True)
        plain_result = decryptor.decrypt(encrypted_matrix)
        pod_result = batch_encoder.decode(plain_result)
        assert pod_result[0] == 0
        assert pod_result[1] == 4
        assert pod_result[2] == 5
        assert pod_result[3] == 6
        assert decryptor.invariant_noise_budget(encrypted_matrix) <= 53


class TestCKKS(unittest.TestCase):
    def test_example_ckks_1(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("CKKS")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus(heal.coeff_modulus_128(8192))
        assert parms.coeff_modulus()[0].bit_count() == 55

        # Create context
        context = heal.Context(parms).context
        assert context.parameters_set()

        # Create keys
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()
        relin = keygen.relin_keys(60)

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)

        # Encode using CKKS
        encoder = heal.CKKSEncoder(context)
        assert encoder.slot_count() == 4096
        input = heal.VectorDouble()
        input.append(0.0)
        input.append(1.1)
        input.append(2.2)
        input.append(3.3)
        scale = 2 ** 60
        plain = encoder.encode(input, scale=scale)

        encrypted = encryptor.encrypt(plain)
        assert plain.parms_id()
        assert plain.scale() == 2 ** 60
        assert encrypted.parms_id()
        assert encrypted.scale() == 2 ** 60

        evaluator.square(encrypted, inplace=True)
        evaluator.relinearize(encrypted, relin, inplace=True)
        plain = decryptor.decrypt(encrypted)
        input = encoder.decode(plain)
        assert math.isclose(input[1], 1.21)
        assert math.isclose(input[2], 4.84)
        assert math.isclose(input[3], 10.89)

        evaluator.mod_switch_to_next(encrypted, inplace=True)
        plain = decryptor.decrypt(encrypted)
        input = encoder.decode(plain)
        assert math.isclose(input[1], 1.21)

        # wrapper can't return reference to scale for direct modification here.

    def test_example_ckks_2(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("CKKS")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus(heal.coeff_modulus_128(8192))
        assert parms.coeff_modulus()[0].bit_count() == 55

        # Create context
        context = heal.Context(parms).context
        assert context.parameters_set()

        # Create keys
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()
        relin = keygen.relin_keys(60)

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)

        # Encode using CKKS
        encoder = heal.CKKSEncoder(context)
        assert encoder.slot_count() == 4096
        input = heal.VectorDouble()
        input.append(0.0)
        input.append(1.1)
        input.append(2.2)
        input.append(3.3)
        scale = 2 ** 60
        plain = encoder.encode(input, scale=scale)

        encrypted = encryptor.encrypt(plain)
        assert encrypted.scale() == 2 ** 60

        output = heal.VectorDouble()
        for i in range(2, 6, 2):
            evaluator.square(encrypted, inplace=True)
            # relinearize before rescaling
            evaluator.relinearize(encrypted, relin, inplace=True)
            evaluator.rescale_to_next(encrypted, inplace=True)
            plain = decryptor.decrypt(encrypted)
            output = encoder.decode(plain)
            assert math.isclose(output[1], input[1] ** i)

        # Perform final square without relinearizing
        # Unable to relinearize with relin_keys at this point due to large decomposition bit count
        evaluator.rescale_to_next(encrypted, inplace=True)
        evaluator.square(encrypted, inplace=True)
        plain = decryptor.decrypt(encrypted)
        output = encoder.decode(plain)
        # Note loss of precision
        assert math.isclose(output[1], 2.1305994861546176, abs_tol=0.01, rel_tol=0.01)

    def test_example_ckks_3(self):
        # In this example our goal is to evaluate the polynomial PI*x^3 + 0.4x + 1 on
        # an encrypted input x for 4096 equidistant points x in the interval [0, 1].

        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("CKKS")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus([heal.small_mods_40bit(0), heal.small_mods_40bit(1),
                                 heal.small_mods_40bit(2), heal.small_mods_40bit(3)])

        # Create context
        context = heal.Context(parms).context
        assert context.parameters_set()

        # Create keys
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()
        relin = keygen.relin_keys(60)

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)
        encoder = heal.CKKSEncoder(context)
        slot_count = encoder.slot_count()
        assert slot_count == 4096
        input = heal.VectorDouble()
        input.reserve(slot_count)
        for i in range(0, slot_count):
            input.append(0.0002442 * i)
        scale = parms.coeff_modulus()[-1].value()
        assert scale == 1099502714881
        plain_x = encoder.encode(input, scale=scale)
        encrypted_x1 = encryptor.encrypt(plain_x)

        plain_coeff3 = encoder.encode(3.14159265, scale=scale)
        plain_coeff1 = encoder.encode(0.4, scale=scale)
        plain_coeff0 = encoder.encode(1.0, scale=scale)

        encrypted_x3 = evaluator.square(encrypted_x1)
        encrypted_x3 = evaluator.relinearize(encrypted_x3, relin)
        encrypted_x3 = evaluator.rescale_to_next(encrypted_x3)

        # encrypted_x3 is now at different encryption parameters than encrypted_x1, preventing multiplication.
        encrypted_x1_coeff3 = evaluator.multiply_plain(encrypted_x1, plain_coeff3)
        evaluator.rescale_to_next(encrypted_x1_coeff3, inplace=True)

        # Encrypted x3 and encrypted_x1_coeff3 now have the same scale and encryption parameters so we can multiply
        evaluator.multiply(encrypted_x3, encrypted_x1_coeff3, inplace=True)
        encrypted_x3 = evaluator.relinearize(encrypted_x3, relin)
        encrypted_x3 = evaluator.rescale_to_next(encrypted_x3)

        # Compute degree one term.
        evaluator.multiply_plain(encrypted_x1, plain_coeff1, inplace=True)
        evaluator.rescale_to_next(encrypted_x1, inplace=True)

        # Encryption parameters for all terms are currently different.
        # Example proceeds to modify scale directly - ending here.

    def test_ckks_multiply_4(self):
        # Create random number generator with fixed seed
        rngf = heal.FastPRNGFactory(1, 1)

        # Configure encryption parameters
        parms = heal.EncryptionParameters("CKKS")
        parms.set_random_generator(rngf)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus(heal.coeff_modulus_128(8192))
        assert parms.coeff_modulus()[0].bit_count() == 55

        # Create context
        context = heal.Context(parms).context
        assert context.parameters_set()

        # Create keys
        keygen = heal.KeyGenerator(context)
        public = keygen.public_key()
        secret = keygen.secret_key()
        relin = keygen.relin_keys(60)

        encryptor = heal.Encryptor(context, public)
        evaluator = heal.Evaluator(context)
        decryptor = heal.Decryptor(context, secret)

        # Encode using CKKS
        encoder = heal.CKKSEncoder(context)
        assert encoder.slot_count() == 4096
        input = heal.VectorDouble()
        input_2 = heal.VectorDouble()
        input_3 = heal.VectorDouble()
        input_4 = heal.VectorDouble()
        input.append(1.0)
        input_2.append(1.0)
        input_3.append(1.0)
        input_4.append(1.0)
        scale = 2 ** 50
        plain = encoder.encode(input, scale=scale)

        encrypted_1 = encryptor.encrypt(plain)
        encrypted_2 = encryptor.encrypt(plain)
        encrypted_3 = encryptor.encrypt(plain)
        encrypted_4 = encryptor.encrypt(plain)

        result1 = evaluator.multiply(encrypted_1, encrypted_2)
        result1 = evaluator.relinearize(result1, relin)
        result1 = evaluator.rescale_to_next(result1)

        test = decryptor.decrypt(result1)
        test = encoder.decode(test)
        assert math.isclose(test[0], 1.0, abs_tol=0.001, rel_tol=0.001)

        # encrypted_3 = evaluator.rescale_to_next(encrypted_3) # Results in wrong answer in next assert
        encrypted_3 = evaluator.mod_switch_to(encrypted_3, result1.parms_id())

        result2 = evaluator.multiply(result1, encrypted_3)
        result2 = evaluator.relinearize(result2, relin)
        result2 = evaluator.rescale_to_next(result2)

        test = decryptor.decrypt(result2)
        test = encoder.decode(test)
        assert math.isclose(test[0], 1.0, abs_tol=0.001, rel_tol=0.001)

        encrypted_4 = evaluator.mod_switch_to(encrypted_4, result2.parms_id())

        result3 = evaluator.multiply(result2, encrypted_4)
        result3 = evaluator.relinearize(result3, relin)
        result3 = evaluator.rescale_to_next(result3)

        test = decryptor.decrypt(result3)
        test = encoder.decode(test)
        assert math.isclose(test[0], 1.0, abs_tol=0.001, rel_tol=0.001)


if __name__ == '__main__':
    unittest.main()
