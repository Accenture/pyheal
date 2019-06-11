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
    print("\n\n")

    a, b = 10, 25

    # normal operation
    r = a + b
    print("{a}+{b} = {r}".format(a=a, b=b, r=r))

    ea = encryptor_encoder.encode(a)
    eb = encryptor_encoder.encode(b)

    # encrypted operation
    er = ea + eb
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # encrypted operation with unencrypted number
    er = ea + b
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # operation with unencrypted number
    er = a + eb
    print("{a})+{b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))


    # Subtract two numbers
    print("\n\n")
    # normal operation
    r = a - b
    print("{a} - {b} = {r}".format(a=a, b=b, r=r))

    # encrypted operation
    er = ea - eb
    print("{a} - {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # encrypted operation with unencrypted number
    er = ea - b
    print("{a} - {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # operation with unencrypted number
    er = a - eb
    print("{a} - {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))


    # Multiply two numbers
    print("\n\n")
    # normal operation
    r = a * b
    print("{a} * {b} = {r}".format(a=a, b=b, r=r))

    # encrypted operation
    er = ea * eb
    print("{a} * {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # encrypted operation with unencrypted number
    er = ea * b
    print("{a} * {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted r = {r}".format(r=decryptor_decoder.decode(er)))

    # operation with unencrypted number
    er = a * eb
    print("{a} * {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))


    # Division two numbers
    print("\n\n")
    # normal operation
    r = a / b
    print("{a} / {b} = {r}".format(a=a, b=b, r=r))

    # encrypted operation
    try:
        er = ea / eb
    except ValueError:
        print("Cannot perform {a} / {b}".format(a=ea, b=eb))


    # encrypted operation with unencrypted number
    er = ea / b
    print("{a} / {b} = {r}".format(a=ea, b=eb, r=er))
    print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))

    # operation with unencrypted number
    try:
        er = a / eb
    except TypeError:
        print("Cannot perform {a} / {b}".format(a=ea, b=eb))


    # Power of encrypted number
    #   exponent need to be integers and a number above 0
    #   large exponents won't work
    print("\n\n")

    for p in range(9):
        r = a ** p

        print("{a}^{p} = {r}".format(a=a, p=p, r=r))
        er = ea ** p
        print("{a}^{p} = {r}".format(a=ea, p=p, r=er))
        print("\tDecrypted = {r}".format(r=decryptor_decoder.decode(er)))


    # Calculate the sum and mean of a list
    print("\n\n")
    l = [1,2,3,4,5,6,7,8,9]
    s = sum(l)
    m = sum(l)/len(l)

    print("List: {l}".format(l=l))
    print("Sum = {s}".format(s=s))
    print("Mean = {m}".format(m=m))

    el = encryptor_encoder.encode(l)
    es = sum(el)
    em = sum(el) / len(el)

    print("List: {l}".format(l=el))
    print("Sum = {s}".format(s=es))
    print("\tDecrypted = {s}".format(s=decryptor_decoder.decode(es)))
    print("Mean = {m}".format(m=em))
    print("\tDecrypted = {m}".format(m=decryptor_decoder.decode(em)))




if __name__ == "__main__":
    main()



