import unittest
import random
import math
import time

random.seed(37733)

from pyheal import wrapper as ph, encoders as encoders

VALID_OPERATIONS = '+-*^'
N_RANDOM_TESTS = 2
N_MAX_CALC_RUNNING_NUMBERS = 4

RANGE_TEST = [('OneZero', 1, 3), ('Small', 10, 2), ('Medium', 1000, 0)]  # ('Large',1000000)]

ALL_OPER_TESTS = [('+ only', '+'), ('- only', '-'), ('+ and -', '+-'), ('* only', '*'),
                  ("+-*", '+-*')]  # ,('+-*^','+-*^')

REL_TOL = 0.01
ABS_TOL = 0.01



class HEOperationTests(object):
    def val_handle(self, val, crypt_flag):
        if crypt_flag is None:
            return val, "{}".format(val)
        elif crypt_flag:
            val_ = self.encryptor_encoder.encode(val)

            return val_, "[{}]".format(val)
        else:
            if self.scheme == 'CKKS':
                val_ = self.plaintext_encoder.encode(ph.VectorDouble([val]))
            else:
                val_ = self.plaintext_encoder.encode(val)

            # val_ = self.plaintext_encoder.encode(val)

            return val_, "({})".format(val)

    def run_oper_test(self, vs, os, cfs=None):
        if cfs is None:
            cfs = [None for _ in vs]
        assert len(vs) + len(cfs) >= 2, "Can't have all empty stacks"

        res, s_calc = self.val_handle(vs[0], cfs[0])

        for val, oper, crypt_flag in zip(vs[1:], os, cfs[1:]):
            val_mod, s_calc_ = self.val_handle(val, crypt_flag)

            s_calc = " ".join([s_calc, oper, s_calc_])
            if oper == '+':
                res = res + val_mod
            elif oper == '-':
                res = res - val_mod
            elif oper == '*':
                res = res * val_mod
            elif oper == '/':
                res = res / val_mod
            elif oper == '^':
                # here val should be a raw number (not encrypted, no plaintext)
                if self.scheme == 'CKKS' and val > 2:
                    raise ValueError("CKK cannot exponentiate higher than 2, please adjust test accordingly")
                res = res ** val
            else:
                AssertionError('Operation {} not supported'.format(oper))

        return res, s_calc

    def run_list_summation(self, list_size, zero_percent, n_repeats=1000):

        non_zero_vals = list(range(1, 1000))
        list_values = [0] + non_zero_vals
        weights = [zero_percent] + [(1-zero_percent)/len(non_zero_vals)] *len(non_zero_vals)

        values = random.choices(list_values, weights=weights, k=list_size)

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                res = sum(values)
        finally:
            steps_per_min_unencrypted = i / (time.time() - stime_)
            print("Sum unencrypted: list Size {}: {:.2f} steps/sec".format(list_size, steps_per_min_unencrypted))

        evalues = self.encryptor_encoder.encode(values)

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                res = sum(evalues)
        finally:
            steps_per_min_encrypted = i / (time.time() - stime_)
            print("Sum encrypted: list Size {}: {:.2f} steps/sec".format(list_size, steps_per_min_encrypted))


    def run_zero_and_one_operations(self, operation, n_repeats = 1000):
        encoder1 = self.encryptor_encoder
        encoder2 = self.plaintext_encoder

        v1 = 20.0
        v2 = 30.0

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                if operation == "*":
                    res = v1 * v2
                elif operation == "+":
                    res = v1 + v2
        finally:
            steps_per_min_unencrypted = i/(time.time() - stime_)
            print("{} Unencrypted: {:.2f} steps/sec".format(operation, steps_per_min_unencrypted))


        ev1 = encoder1.encode(v1)
        ev2 = encoder2.encode(v2)

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                if operation == "*":
                    res = ev1 * ev2
                elif operation == "+":
                    res = ev1 + ev2

        finally:
            steps_per_min_encrypted = i/(time.time() - stime_)
            print("{} Encrypted Normal: {:.2f} steps/sec".format(operation, steps_per_min_encrypted))

        v1 = 20.0
        v2 = 0.0

        ev1 = encoder1.encode(v1)
        ev2 = encoder2.encode(v2)

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                if operation == "*":
                    res = ev1 * ev2
                elif operation == "+":
                    res = ev1 + ev2
        finally:
            steps_per_min_encrypted_zero = i/(time.time() - stime_)
            print("{} Encrypted Zeros: {:.2f} steps/sec".format(operation, steps_per_min_encrypted_zero))

        v1 = 20.0
        v2 = 1.0

        ev1 = encoder1.encode(v1)
        ev2 = encoder2.encode(v2)

        stime_ = time.time()
        try:
            for i in range(n_repeats):
                if operation == "*":
                    res = ev1 * ev2
                elif operation == "+":
                    res = ev1 + ev2
        finally:
            steps_per_min_encrypted_one = i/(time.time() - stime_)
            print("{} Encrypted Ones: {:.2f} steps/sec".format(operation, steps_per_min_encrypted_one))

    def test_zero_and_one_operations(self):
        for zero_percent in [0.0, 0.125, 0.25, 0.50]:
            for list_size in [1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
                self.run_list_summation(list_size=list_size, zero_percent=zero_percent, n_repeats=500)

        self.run_zero_and_one_operations("+", n_repeats=1000)
        self.run_zero_and_one_operations("*", n_repeats=1000)



    def simple_calc_encoders(self, encoder1, encoder2):

        if encoder1 is None:
            encoder1 = self.encryptor_encoder

        if encoder2 is None:
            encoder2 = self.encryptor_encoder

        v1 = 35
        v2 = -10

        ev1 = encoder1.encode(v1)
        ev2 = encoder2.encode(v2)

        res = v1 + v2
        print('{} + {} = {}'.format(v1, v2, res))
        eres_ = ev1 + ev2
        eres = self.decryptor_decoder.decode(eres_)
        print('{} + {} = {} <- E'.format(v1, v2, eres))
        self.assertTrue(math.isclose(res, eres, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res, v2=eres))

        res = v1 - v2
        print('{} - {} = {}'.format(v1, v2, res))
        eres_ = ev1 - ev2

        eres = self.decryptor_decoder.decode(eres_)
        print('{} - {} = {} <- E'.format(v1, v2, eres))
        self.assertTrue(math.isclose(res, eres, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res, v2=eres))

        res = v1 * v2
        print('{} * {} = {} <- E'.format(v1, v2, res))
        eres_ = ev1 * ev2

        eres = self.decryptor_decoder.decode(eres_)
        print('{} * {} = {} <- E'.format(v1, v2, eres))
        self.assertTrue(math.isclose(res, eres, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res, v2=eres))

        for power in [2, 3, 5, 6]:
            if self.scheme == 'CKKS' and power > 2:
                continue

            res = v1 ** power
            print('{}^{} = {}'.format(v1, power, res))
            eres_ = ev1 ** power

            eres = self.decryptor_decoder.decode(eres_)
            print('{}^{} = {} <- E'.format(v1, power, eres))
            self.assertTrue(math.isclose(res, eres, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                            msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res,
                                                                                                         v2=eres))

    def test_SimpleCalc_Encrypted_Encrypted(self):
        self.simple_calc_encoders(encoder1=self.encryptor_encoder, encoder2=self.encryptor_encoder)

    def test_SimpleCalc_Encrypted_PlainText(self):
        self.simple_calc_encoders(encoder1=self.encryptor_encoder, encoder2=self.plaintext_encoder)

    def test_SimpleCalc_Encrypted_Number(self):
        class empty_encoder(object):
            @classmethod
            def encode(self, x): return x

            @classmethod
            def decode(self, x): return x

        self.simple_calc_encoders(encoder1=self.encryptor_encoder, encoder2=empty_encoder)

    def perform_one_test(self, value_stack, operation_stack, rname="Manual", ntype=int, nvoper=VALID_OPERATIONS,
                         assert_places=3):
        res_raw, s_calc = self.run_oper_test(value_stack, operation_stack, cfs=None)
        print(s_calc, "=", res_raw)

        # print("All Encrypted: {} {} {}".format(rname, ntype, nvoper))
        res_, s_calc = self.run_oper_test(value_stack, operation_stack, cfs=[True for _ in range(len(value_stack))])
        res_encrypt_all = self.decryptor_decoder.decode(res_)
        print(s_calc, "=", res_encrypt_all)

        self.assertTrue(math.isclose(res_raw, res_encrypt_all, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res_raw,
                                                                                                     v2=res_encrypt_all))

        # print("First Encrypted {} {} {}".format(rname, ntype, nvoper))
        res_, s_calc = self.run_oper_test(value_stack, operation_stack,
                                          cfs=[True] + [False for _ in range(len(value_stack) - 1)])
        res_encrypt_first = self.decryptor_decoder.decode(res_)
        print(s_calc, "=", res_encrypt_first)
        self.assertTrue(math.isclose(res_raw, res_encrypt_first, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res_raw,
                                                                                                     v2=res_encrypt_first))

        # print("First Encrypted {} {} {}".format(rname, ntype, nvoper))
        res_, s_calc = self.run_oper_test(value_stack, operation_stack,
                                          cfs=[True] + [None for _ in range(len(value_stack) - 1)])
        res_encrypt_first = self.decryptor_decoder.decode(res_)
        print(s_calc, "=", res_encrypt_first)
        self.assertTrue(math.isclose(res_raw, res_encrypt_first, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res_raw,
                                                                                                     v2=res_encrypt_first))

        # print("Random Encrypted (at least one of the first two) {} {} {}".format(rname, ntype, nvoper))
        crypt_flag_stack = [0]
        # while sum(crypt_flag_stack[:2]) == 0:
        while sum(map(lambda x: int(x) if x is not None else 0, (crypt_flag_stack[:2]))) == 0:

            crypt_flag_stack = random.choices([False, True, None], k=len(value_stack))

        res_, s_calc = self.run_oper_test(value_stack, operation_stack, cfs=crypt_flag_stack)
        res_encrypted = self.decryptor_decoder.decode(res_)
        print(s_calc, "=", res_encrypted)
        self.assertTrue(math.isclose(res_raw, res_encrypted, rel_tol=REL_TOL, abs_tol=ABS_TOL),
                        msg="Values are significantly different to each other: {v1} and {v2}".format(v1=res_raw,
                                                                                                     v2=res_encrypted))

    def test_OneRandomCalc(self):

        value_stack = [1, 2, 3, 4, 2]
        operation_stack = ['+', '*', '-', '^']

        self.perform_one_test(value_stack, operation_stack, "Manual", int, ''.join(list(set(operation_stack))))

    def test_ManyRandomCalc(self):

        for nvoper, valid_operations in ALL_OPER_TESTS:
            print("Testing Operations {}".format(nvoper))
            for ntype, randfunc in [(int, random.randint), (float, random.uniform)]:
                print("Testing {}".format(ntype))
                for rname, range_max, assert_places in RANGE_TEST:
                    print("Testing range {rname} [-{range}:{range}]".format(rname=rname, range=range_max))
                    for test_no in range(N_RANDOM_TESTS):
                        n_numbers_ = random.randint(2, N_MAX_CALC_RUNNING_NUMBERS)
                        value_stack = [randfunc(-range_max, range_max) for _ in range(n_numbers_)]
                        operation_stack = random.choices(valid_operations, k=n_numbers_ - 1)

                        self.perform_one_test(value_stack, operation_stack, rname, ntype, nvoper, assert_places)

    def test_FourMult(self):
        value_stack = [2, 2, 2, 2]
        operation_stack = ['*', '*', '*']

        self.perform_one_test(value_stack, operation_stack, "Manual", int, ''.join(list(set(operation_stack))))

    def test_reversed_order(self):
        value_stack = [2, 2, 2, 2]
        encrypted_stack = []
        for val in value_stack:
            encrypted_stack.append(self.encryptor_encoder.encode(val))

        result1 = encrypted_stack[0] * encrypted_stack[1]
        result2 = encrypted_stack[2] * result1
        result3 = encrypted_stack[3] - result2
        output = self.decryptor_decoder.decode(result3)
        print(output)
        assert math.isclose(output, -6, rel_tol=0.0001)


class TestHelpers_BFV(unittest.TestCase, HEOperationTests):
    def setUp(self):
        self.scheme = 'BFV'

        poly_modulus = 1 << 12
        coeff_modulus_128 = 1 << 12
        plain_modulus = 1 << 10

        parms = ph.EncryptionParameters(scheme_type=self.scheme)
        parms.set_poly_modulus(poly_modulus)
        parms.set_coeff_modulus(ph.coeff_modulus_128(coeff_modulus_128))
        parms.set_plain_modulus(plain_modulus)

        seal_context_ = ph.Context(parms).context

        keygen = ph.KeyGenerator(seal_context_)
        public_key_ = keygen.public_key()
        secret_key_ = keygen.secret_key()
        relin_keys_ = keygen.relin_keys(decomposition_bit_count=16, count=2)

        self.plaintext_encoder = encoders.PlainTextEncoder(
            encoder=ph.FractionalEncoder(smallmod=ph.SmallModulus(plain_modulus),
                                         poly_modulus_degree=poly_modulus,
                                         integer_coeff_count=64,
                                         fraction_coeff_count=32,
                                         base=2))

        encryptor_ = ph.Encryptor(ctx=seal_context_, public=public_key_)
        decryptor_ = ph.Decryptor(ctx=seal_context_, secret=secret_key_)

        evaluator_ = ph.Evaluator(ctx=seal_context_)

        self.encryptor_encoder = encoders.EncryptorOp(plaintext_encoder=self.plaintext_encoder,
                                                      encryptor=encryptor_,
                                                      evaluator=evaluator_,
                                                      relin_key=relin_keys_
                                                      )

        self.decryptor_decoder = encoders.Decryptor(plaintext_encoder=self.plaintext_encoder, decryptor=decryptor_)

    def tearDown(self):
        pass


class TestHelpers_CKKS(unittest.TestCase, HEOperationTests):
    def setUp(self):
        self.scheme = "CKKS"

        parms = ph.EncryptionParameters(scheme_type=self.scheme)
        parms.set_poly_modulus(8192)
        parms.set_coeff_modulus([ph.small_mods_40bit(0), ph.small_mods_40bit(1),
                                 ph.small_mods_40bit(2), ph.small_mods_40bit(3),
                                 ph.small_mods_40bit(4), ph.small_mods_40bit(5)
                                 ])

        seal_context_ = ph.Context(parms).context

        keygen = ph.KeyGenerator(seal_context_)
        public_key_ = keygen.public_key()
        secret_key_ = keygen.secret_key()
        relin_keys_ = keygen.relin_keys(decomposition_bit_count=16, count=2)


        self.plaintext_encoder = encoders.PlainTextEncoder(encoder=ph.CKKSEncoder(ctx=seal_context_), scale=2 ** 40)

        encryptor_ = ph.Encryptor(ctx=seal_context_, public=public_key_)
        decryptor_ = ph.Decryptor(ctx=seal_context_, secret=secret_key_)

        evaluator_ = ph.Evaluator(ctx=seal_context_)

        self.encryptor_encoder = encoders.EncryptorOp(plaintext_encoder=self.plaintext_encoder,
                                                      encryptor=encryptor_,
                                                      evaluator=evaluator_,
                                                      relin_key=relin_keys_,
                                                      )

        self.decryptor_decoder = encoders.Decryptor(plaintext_encoder=self.plaintext_encoder, decryptor=decryptor_)

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
