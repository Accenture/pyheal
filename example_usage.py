from pyheal import wrapper
from pyheal import encoders


def get_encryptor_decryptor():
    """
        Return an encryptor and a decryptor object for the same scheme
    """

    scheme = 'BFV'

    poly_modulus = 1 << 12
    coeff_modulus_128 = 1 << 12
    plain_modulus = 1 << 10

    parms = wrapper.EncryptionParameters(scheme_type=scheme)

    parms.set_poly_modulus(poly_modulus)
    parms.set_coeff_modulus(wrapper.coeff_modulus_128(coeff_modulus_128))
    parms.set_plain_modulus(plain_modulus)

    seal_context_ = wrapper.Context(parms).context

    keygen = wrapper.KeyGenerator(seal_context_)

    plaintext_encoder = encoders.PlainTextEncoder(
        encoder=wrapper.FractionalEncoder(smallmod=wrapper.SmallModulus(plain_modulus),
                                          poly_modulus_degree=poly_modulus,
                                          integer_coeff_count=64,
                                          fraction_coeff_count=32,
                                          base=2)
    )

    encryptor_encoder = encoders.EncryptorOp(plaintext_encoder=plaintext_encoder,
                                             encryptor=wrapper.Encryptor(ctx=seal_context_, public=keygen.public_key()),
                                             evaluator=wrapper.Evaluator(ctx=seal_context_),
                                             relin_key=keygen.relin_keys(decomposition_bit_count=16, count=2)
                                             )


    decryptor_decoder = encoders.Decryptor(plaintext_encoder=plaintext_encoder,
                                           decryptor=wrapper.Decryptor(ctx=seal_context_, secret=keygen.secret_key())
                                           )

    return encryptor_encoder, decryptor_decoder

def main():

    encryptor_encoder, decryptor_decoder = get_encryptor_decryptor()

    # Sum two numbers

    a, b = 10, 25

    r = a + b
    print("{a}+{b} = {r}".format(a=a, b=b, r=r))

    ea = encryptor_encoder.encode(a)
    eb = encryptor_encoder.encode(b)

    er = ea + eb
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("Decrypted r = {r}".format(decryptor_decoder.decode(er)))

    er = ea + b
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("Decrypted r = {r}".format(decryptor_decoder.decode(er)))

    er = a + eb
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("Decrypted r = {r}".format(decryptor_decoder.decode(er)))





    #



if __name__ == "__main__":
    main()



