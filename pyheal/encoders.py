from abc import ABC, abstractmethod

import seal_wrapper as seal
from pyheal import ciphertext_op as cop, wrapper as ph


class ABSDecoder(ABC):
    @abstractmethod
    def _decode(self, dt):
        ...


class BaseDecoder(ABSDecoder):
    def __init__(self, decoder):
        self._decoder = decoder

    def _decode(self, dt):
        return dt

    def decode(self, dt):
        """
         Decode data
        :param dt: data to be decoded or list of data points to be decoded
        :return: decoded data
        """
        if isinstance(dt, list):
            return [self.decode(v_) for v_ in dt]
        else:
            return self._decode(dt)


class ABSEncoder(ABC):
    @abstractmethod
    def _encode(self, dt):
        ...


class BaseEncoder(ABSEncoder):
    def __init__(self, encoder):
        self._encoder = encoder

    def _encode(self, dt):
        return dt

    def encode(self, dt, **kwargs):
        """
         Encode data
        :param dt: numeric data or list of numbers
        :return: encoded data
        """

        # Check if data is plaintext
        if isinstance(dt, list):
            return [self.encode(v_, **kwargs) for v_ in dt]
        else:
            return self._encode(dt, **kwargs)


class PlainTextEncoder(BaseEncoder, BaseDecoder):
    """
    Plaintext encoder to convert raw values into Plaintext objects containing an encoded polynomial.
    """
    def __init__(self, encoder, scale=None):
        """
        Create a Plaintext encoder for converting raw values into encoded polynomials.
        :param encoder: A pyheal.he_wrappers.wrapper such as IntegerEncoder, FractionalEncoder, CKKSEncoder.
        :param scale: Encoder scale if using CKKS.
        """
        BaseEncoder.__init__(self, encoder=encoder)
        BaseDecoder.__init__(self, decoder=encoder)
        self.scale = scale

    def _encode(self, dt, **kwargs):
        if isinstance(self._encoder, ph.CKKSEncoder):
            if 'scale' not in kwargs:
                kwargs['scale'] = self.scale
            return self._encoder.encode(dt, **kwargs)
        else:
            return self._encoder.encode(dt)

    def _decode(self, dt):
        res = self._decoder.decode(dt)
        return res


class Encryptor(BaseEncoder):
    def __init__(self, plaintext_encoder=None, encryptor=None):
        BaseEncoder.__init__(self, encoder=encryptor)
        self._plaintext_encoder = plaintext_encoder

    def get_plaintext_encoder(self):
        self._plaintext_encoder

    def _encode(self, dt):
        if not isinstance(dt, ph.Plaintext):
            dt = self._plaintext_encoder.encode(dt)

        return self._encoder.encrypt(dt)


class EncryptorOp(Encryptor):
    def __init__(self,
                 plaintext_encoder=None,
                 encryptor=None,
                 evaluator=None,
                 relin_key=None,
                 noise_decoder=None
                 ):
        """
        Create an Encryptor which encrypts Plaintext and returns Ciphertext which are operation friendly.
        :param plaintext_encoder: Plaintext encoder
        :param encryptor: A pyheal.he_wrappers.wrapper Encryptor initialised with the required context.
        :param evaluator: A pyheal.he_wrappers.wrapper Evaluator initialised with the required context.
        :param relin_key: Relinearisation keys.
        :param noise_decoder: A NoiseBudgetDecoder if using BFV.
        """
        super().__init__(plaintext_encoder, encryptor)
        self.evaluator = evaluator
        self.relin_key = relin_key
        self.noise_decoder = noise_decoder

    def _encode(self, dt):
        return cop.CiphertextOp(ciphertext=super()._encode(dt),
                                evaluator=self.evaluator,
                                relin_key=self.relin_key,
                                noise_decoder=self.noise_decoder,
                                encryptor=self,
                                plaintext_encoder=self._plaintext_encoder
                                )


class Decryptor(BaseDecoder):
    def __init__(self, plaintext_encoder=None, decryptor=None):
        """
        Create an Decryptor which decrypts Ciphertext and returns Plaintext.
        :param plaintext_encoder: Plaintext encoder
        :param decryptor: A pyheal.he_wrappers.wrapper Decryptor
        """
        BaseDecoder.__init__(self, decoder=decryptor)
        self._plaintext_encoder = plaintext_encoder

    def get_plaintext_encoder(self):
        self._plaintext_encoder

    def _decode(self, dt):
        if isinstance(dt, ph.Ciphertext):
            plaintext = self._decoder.decrypt(dt)
        elif isinstance(dt, ph.Plaintext):
            plaintext = dt
        else:
            raise AttributeError("Decryptor should decode a ciphertext or plaintext")

        res = self._plaintext_encoder.decode(plaintext)
        if isinstance(res, seal.VectorDouble):
            return res[0]  # todo: fix this eventually. Now only returns one value
        else:
            return res


class NoiseBudgetDecoder(BaseDecoder):
    def __init__(self, decryptor):
        BaseDecoder.__init__(self, decoder=decryptor)

    def _decode(self, dt):
        return self._decoder.invariant_noise_budget(dt)  # if list then it needs to min later
