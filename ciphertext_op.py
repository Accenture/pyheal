import copy
import math
from functools import wraps

import wrapper as ph

import seal_wrapper as seal


class CiphertextOp(ph.Ciphertext):
    """
    CiphertextOp is a wrapper class for homomorphic encryption Ciphertexts which
     enable direct operations similar to numbers (i.e. "+", "-", "*", "^").
    Note that operations must still work within the constraints of the
    homomorphic encryption scheme or the decrypted result will not be remotely accurate.
    """
    def __init__(self,
                 ciphertext=None, ctx=None, parms_id=None,
                 size_capacity=None, pool=None,
                 evaluator=None,
                 relin_key=None, noise_decoder=None,
                 encryptor=None, plaintext_encoder=None
                 ):
        super().__init__(ciphertext=ciphertext, ctx=ctx, parms_id=parms_id, size_capacity=size_capacity, pool=pool)
        self.set_params(evaluator=evaluator, relin_key=relin_key,
                        noise_decoder=noise_decoder,
                        encryptor=encryptor, plaintext_encoder=plaintext_encoder)

    def set_params(self, evaluator, relin_key=None, noise_decoder=None, encryptor=None,
                   plaintext_encoder=None):
        self.evaluator = evaluator
        self.relin_keys = relin_key
        self.noise_decoder = noise_decoder
        self.encryptor = encryptor
        self.plaintext_encoder = plaintext_encoder

    def get_params(self):
        return dict(evaluator=self.evaluator,
                    relin_key=self.relin_keys,
                    noise_decoder=self.noise_decoder,
                    encryptor=self.encryptor,
                    plaintext_encoder=self.plaintext_encoder
                    )

    def ensure_return_ciphertext_op(func):
        @wraps(func)
        def func_wrapper(self, *args, **kwargs):
            res = CiphertextOp(ciphertext=func(self, *args, **kwargs),
                               evaluator=self.evaluator,
                               relin_key=self.relin_keys,
                               noise_decoder=self.noise_decoder,
                               encryptor=self.encryptor,
                               plaintext_encoder=self.plaintext_encoder)

            return res

        return func_wrapper

    @staticmethod
    def _rescale(this, other, scale_out_of_bounds=False):

        if not (isinstance(other, seal.Ciphertext) or isinstance(other, seal.Plaintext)):
            return other
            # raise ValueError('Unknown type to rescale: Type {}'.format(type(other)))

        if isinstance(other, seal.Plaintext):
            if scale_out_of_bounds:
                this.evaluator.rescale_to_next(this, inplace=True)
            other = this.plaintext_encoder.encode(this.plaintext_encoder.decode(other),
                                                  parms_id=this.parms_id(),
                                                  scale=this.scale()
                                                  )
            return other

        # Only Ciphertext from here on
        this_index = this.evaluator.chain_index(this.parms_id())
        other_index = this.evaluator.chain_index(other.parms_id())

        if this_index == other_index and math.isclose(this.scale(), other.scale()) and not scale_out_of_bounds:
            # All parameters match - proceed.
            return other

        # Guidelines
        # We can multiply a value by 1 to scale it up.
        # We can only switch parms_id down the chain. This reduces the scale.
        # We can only multiply when both values are on the same parms_id.
        # We should keep scale at a reasonable value to avoid scale out of bounds after multiplying

        # Re-scale up via multiplying by 1
        if hasattr(this, '_multiply_one_rescale') and callable(getattr(this, '_multiply_one_rescale')):
            this, other = this._multiply_one_rescale(this, other)
        else:
            this, other = other._multiply_one_rescale(this, other)

        # Switch encryption parameters
        if this_index != other_index:
            # Switch to lowest parameter (we can only shift down the chain).
            if this_index > other_index:
                this = this.evaluator.rescale_to(current=this, parms_id=other.parms_id())
            else:
                other = this.evaluator.rescale_to(current=other, parms_id=this.parms_id())

        # Rescale again if required
        if hasattr(this, '_multiply_one_rescale') and callable(getattr(this, '_multiply_one_rescale')):
            this, other = this._multiply_one_rescale(this, other)
        else:
            this, other = other._multiply_one_rescale(this, other)

        if scale_out_of_bounds:
            # Switch both parameters to next
            for val in [this, other]:
                if val.size() > 2:
                    this.evaluator.relinearize(val, val.relin_keys, inplace=True)
                this.evaluator.rescale_to_next(val, inplace=True)

        return other

    @staticmethod
    def _multiply_one_rescale(this, other):
        if not math.isclose(this.scale(), other.scale()):
            # Rescaling required
            if this.scale() > other.scale():
                factor = this.scale()/other.scale()
                if factor > 1e30:
                    # Factor's too big for a single encoding attempt to execute in multiple steps
                    plain_one = this.plaintext_encoder.encode(1, parms_id=other.parms_id(), scale=factor/5)
                    other = this.evaluator.multiply_plain(other, plain_one, inplace=True)
                    plain_one = this.plaintext_encoder.encode(1, parms_id=other.parms_id(), scale=5)
                    other = this.evaluator.multiply_plain(other, plain_one, inplace=True)
                else:
                    # Scale other up
                    plain_one = this.plaintext_encoder.encode(1, parms_id=other.parms_id(), scale=this.scale()/other.scale())
                    other = this.evaluator.multiply_plain(other, plain_one, inplace=True)
            else:
                factor = other.scale()/this.scale()
                if factor > 1e30:
                    plain_one = this.plaintext_encoder.encode(1, parms_id=this.parms_id(), scale=factor/5)
                    this = this.evaluator.multiply_plain(this, plain_one, inplace=True)
                    plain_one = this.plaintext_encoder.encode(1, parms_id=this.parms_id(), scale=5)
                    this = this.evaluator.multiply_plain(this, plain_one, inplace=True)
                else:
                    plain_one = this.plaintext_encoder.encode(1, parms_id=this.parms_id(), scale=other.scale()/this.scale())
                    this = this.evaluator.multiply_plain(this, plain_one, inplace=True)
        return this, other

    @ensure_return_ciphertext_op
    def _internal_add(self, other, inplace):
        other = CiphertextOp._rescale(self, other)
        if isinstance(other, seal.Ciphertext):
            res = self.evaluator.add(self, other, inplace=inplace)
        elif isinstance(other, seal.Plaintext):
            # Note: add/sum to zero is internally optimised
            res = self.evaluator.add_plain(self, other, inplace=inplace)
        elif self.plaintext_encoder is not None:
            res = self._internal_add(self.plaintext_encoder.encode(other), inplace=inplace)
        else:
            raise ValueError("Addition with type {} unsupported without passing an appropriate plaintext encoder".format(type(other)))

        return res

    @ensure_return_ciphertext_op
    def _internal_sub(self, other, inplace):
        other = CiphertextOp._rescale(self, other)
        if isinstance(other, seal.Ciphertext):
            res = self.evaluator.sub(self, other, inplace=inplace)
        elif isinstance(other, seal.Plaintext):
            # Note: add/sum to zero is internally optimised
            res = self.evaluator.sub_plain(self, other, inplace=inplace)
        elif self.plaintext_encoder is not None:
            res = self._internal_sub(self.plaintext_encoder.encode(other), inplace=inplace)
        else:
            raise ValueError("Substractiom with type {} unsupported without passing an appropriate plaintext encoder".format(type(other)))

        return res

    @ensure_return_ciphertext_op
    def _internal_mul(self, other, inplace):
        other = CiphertextOp._rescale(self, other)
        if isinstance(other, seal.Ciphertext):

            while self.evaluator.chain_index(self.parms_id()) > 0:
                try:
                    res = self.evaluator.multiply(self, other, inplace=inplace)
                    break
                except ValueError:
                    # Scale out of bounds, rescale and retry
                    other = CiphertextOp._rescale(self, other, scale_out_of_bounds=True)
                    continue

        elif isinstance(other, seal.Plaintext):
            if other.is_zero():
                if self.encryptor is not None:
                    res = self.encryptor.encode(0)  # unsure how this behaves on a *=
                else:
                    raise AttributeError("Plain is zero, and no encryptor given ")
            else:
                # Note: don't test for plain text == 1 (one) this is internally optimised by SEAL
                while self.evaluator.chain_index(self.parms_id()) > 0:
                    try:
                        res = self.evaluator.multiply_plain(self, other, inplace=inplace)
                        break
                    except ValueError:
                        # Scale out of bounds!
                        other = CiphertextOp._rescale(self, other, scale_out_of_bounds=True)
                        continue

        elif self.plaintext_encoder is not None:
            res = self._internal_mul(self.plaintext_encoder.encode(other), inplace=inplace)
        else:
            raise ValueError("Multiplication with type {} unsupported without passing an appropriate plaintext encoder".format(type(other)))

        # if self.noise_decoder is not None:
        #     noise_budget = self.noise_decoder.decode(res)
        #     print("Noise budget in op result: {}".format(noise_budget))

        if 'res' not in vars():
            raise ValueError("Depleted scale or modulus switching chain.")

        if self.relin_keys is not None:
            res = self.evaluator.relinearize(res, self.relin_keys, inplace=True)  # always inplace

        return res

    @ensure_return_ciphertext_op
    def _internal_pow(self, power, inplace):
        if power == 0:
            if self.encryptor is not None:
                return self.encryptor.encode(1)  # unsure how this works inplace
            else:
                raise AttributeError("Power is zero, and no encryptor given ")
        elif power == 1:
            return self if inplace else copy.copy(self)
        elif power == 2:
            res = self.evaluator.square(self, inplace=inplace)
            if self.relin_keys is not None:
                res = self.evaluator.relinearize(res, self.relin_keys, inplace=True)
        else:
            if self.relin_keys is not None:
                res = self.evaluator.exponentiate(self, power, self.relin_keys, inplace=inplace)
            else:
                raise AttributeError("Cannot do higher degrees power without a evaluation key")

        # if self.noise_decoder is not None:
        #     noise_budget = self.noise_decoder.decode(res)
        #     print("Noise budget in op result: {}".format(noise_budget))

        return res

    @ensure_return_ciphertext_op
    def _internal_negate(self, inplace):
        return self.evaluator.negate(self, inplace=inplace)

    def __add__(self, other):
        return self._internal_add(other, inplace=False)

    def __iadd__(self, other):
        return self._internal_add(other, inplace=True)

    def __radd__(self, other):
        if other == 0:
            return self
        else:
            return self.__add__(other)

    def __neg__(self):
        return self._internal_negate(inplace=False)

    def __sub__(self, other):
        return self._internal_sub(other, inplace=False)

    def __isub__(self, other):
        return self._internal_sub(other, inplace=True)

    def __rsub__(self, other):
        if other == 0:
            return self
        else:
            return self.__neg__().__add__(other)

    def __mul__(self, other):
        return self._internal_mul(other, inplace=False)

    def __imul__(self, other):
        return self._internal_mul(other, inplace=True)

    def __rmul__(self, other):
        if other == 0:
            return self
        else:
            return self.__mul__(other)

    def __pow__(self, power):
        return self._internal_pow(power, inplace=False)

    def __ipow__(self, power):
        return self._internal_pow(power, inplace=True)

    @ensure_return_ciphertext_op
    def rescale_to_next(self):
        res = self.evaluator.rescale_to_next(self)
        return res
