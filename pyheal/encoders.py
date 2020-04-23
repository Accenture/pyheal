from abc import ABC, abstractmethod

import numpy as np

import seal_wrapper as seal
from pyheal import ciphertext_op as cop
from pyheal import wrapper



class ABSDecoder(ABC):
    """
        Abstract Decoder
    """
    @abstractmethod
    def _decode(self, dt):
        """
            Decode data
        :param dt: data to decode
        :return: decoded data
        """
        ...


class BaseDecoder(ABSDecoder):
    """
        Base for all decoder implementation
    """
    def __init__(self, decoder):
        """
            Constructor
        :param decoder: decoder from wrapper
        """
        self._decoder = decoder

    def _decode(self, dt):
        """
            Internal decoder, must be overloaded for implementation
        :param dt: data to be decoded
        :return: decoded data
        """
        return dt

    def decode(self, dt):
        """
            Decode data
        :param dt: data to be decoded or list of data points to be decoded
        :return: decoded data
        """
        if isinstance(dt, dict):
            return {k:self.decode(v) for k, v in dt.items()}
        elif isinstance(dt, np.ndarray):
            return np.array(self.decode(dt.tolist()))
        elif isinstance(dt, list):
            return [self.decode(v_) for v_ in dt]
        else:
            return self._decode(dt)


class ABSEncoder(ABC):
    """
        Abstract encoder
    """
    @abstractmethod
    def _encode(self, dt):
        ...


class BaseEncoder(ABSEncoder):
    """
        Base for all encoder implementations
    """
    def __init__(self, encoder):
        """
        Encoder constructor
        :param encoder: encoder from wrapper
        """
        self._encoder = encoder

    def _encode(self, dt):
        """
            Internal encoder implementation, must be overloaded
        :param dt: data to be encoded
        :return: encoded data
        """
        return dt

    def encode(self, dt, **kwargs):
        """
         Encode data
        :param dt: numeric data or list of numbers
        :return: encoded data
        """

        # Check if data is plaintext
        if isinstance(dt, dict):
            return {k:self.encode(v, **kwargs) for k, v in dt.items()}
        elif isinstance(dt, np.ndarray):
            return np.array(self.encode(dt.tolist(), **kwargs))
        elif isinstance(dt, list):
            return [self.encode(v_, **kwargs) for v_ in dt]
        else:
            return self._encode(dt)


class PassthroughEncoder(BaseEncoder, BaseDecoder):
    """
    Passthrough encoder just passthrough the data. Doesn't encode or decode
    does nothing, uses bare BaseEncoder
    """
    def __init__(self):
        """
        PassthroughEncoder constructor
        """
        BaseEncoder.__init__(self, encoder=None)
        BaseDecoder.__init__(self, decoder=None)



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
        """
            Encode data into plaintext
        :param dt: data to be encoded
        :param kwargs: any extra encoded arguments
        :return: encoded data
        """
        if isinstance(self._encoder, wrapper.CKKSEncoder):
            if 'scale' not in kwargs:
                kwargs['scale'] = self.scale
            return self._encoder.encode(dt, **kwargs)
        else:
            return self._encoder.encode(dt)

    def _decode(self, dt):
        """
            Decode plaintext into data
        :param dt: plaintext encoded data
        :return: decoded data
        """
        res = self._decoder.decode(dt)
        return res


class Encryptor(BaseEncoder):
    """
        Class for data encryption
    """
    def __init__(self, plaintext_encoder=None, encryptor=None):
        """
            Constructor
        :param plaintext_encoder: paintext encoder
        :param encryptor: encryptor from wrapper
        """
        BaseEncoder.__init__(self, encoder=encryptor)
        self._plaintext_encoder = plaintext_encoder

    def get_plaintext_encoder(self):
        """
            Return the plaintext encoder/decoder
        """
        self._plaintext_encoder

    def _encode(self, dt):
        """
            Internal function to Encoder / Encrypt the data
        :param dt: data
        :return: encrypted data
        """
        if not isinstance(dt, wrapper.Plaintext):
            dt = self._plaintext_encoder.encode(dt)

        return self._encoder.encrypt(dt)


class EncryptorOp(Encryptor):
    """
        EncryptorOp ensures encrypted data that can be operated using operations in CiphertextOp
    """
    def __init__(self,
                 plaintext_encoder=None,
                 encryptor=None,
                 evaluator=None,
                 relin_key=None
                 ):
        """
        Create an Encryptor which encrypts Plaintext and returns Ciphertext which are operation friendly.

        :param plaintext_encoder: Plaintext encoder
        :param encryptor: A pyheal.he_wrappers.wrapper Encryptor initialised with the required context.
        :param evaluator: A pyheal.he_wrappers.wrapper Evaluator initialised with the required context.
        :param relin_key: Relinearisation keys.
        """
        super().__init__(plaintext_encoder, encryptor)
        self.evaluator = evaluator
        self.relin_key = relin_key

    def _encode(self, dt):
        """
            Internal encoder which ensures the ciphertext is of type CipherTextOp
        :param dt: data
        :return: CipherTextOp data
        """
        return cop.CiphertextOp(ciphertext=super()._encode(dt),
                                evaluator=self.evaluator,
                                relin_keys=self.relin_key,
                                encryptor=self,
                                plaintext_encoder=self._plaintext_encoder
                                )


class Decryptor(BaseDecoder):
    """
        Decryptor, decrypts HE data
    """
    def __init__(self, plaintext_encoder=None, decryptor=None):
        """
        Create an Decryptor which decrypts Ciphertext and returns Plaintext.
        :param plaintext_encoder: Plaintext encoder
        :param decryptor: A pyheal.he_wrappers.wrapper Decryptor
        """
        BaseDecoder.__init__(self, decoder=decryptor)
        self._plaintext_encoder = plaintext_encoder

    def get_plaintext_encoder(self):
        """
                    Return the plaintext encoder/decoder
        """
        self._plaintext_encoder

    def _decode(self, dt):
        """
            Internal decode that ensures an encrypted data or plaintext is decoded to data
        :param dt: ciphertext or plaintext
        :return: data
        """
        if isinstance(dt, wrapper.Ciphertext):
            plaintext = self._decoder.decrypt(dt)
        elif isinstance(dt, wrapper.Plaintext):
            plaintext = dt
        else:
            raise AttributeError("Decryptor should decode a ciphertext or plaintext")

        res = self._plaintext_encoder.decode(plaintext)
        if isinstance(res, seal.VectorDouble):
            return res[0]  # todo: fix this eventually. Now only returns one value
        else:
            return res


class NoiseBudgetDecoder(BaseDecoder):
    """
        NoiseBudgetDecoder returns how much noise is still available in a number
    """
    def __init__(self, decryptor):
        """
            Contruct using a decryptor object (needs the private key)
        :param decryptor:
        """
        BaseDecoder.__init__(self, decoder=decryptor)

    def _decode(self, dt):
        """
            Returns the noise budget left for a encrypted object

        :param dt: encrypted object
        :return: noise budget
        """
        return self._decoder.invariant_noise_budget(dt)  # if list then it needs to min later

