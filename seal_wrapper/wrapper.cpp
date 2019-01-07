#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include "seal/seal.h"
#include "base64.h"

namespace py = pybind11;
using namespace pybind11::literals;
using namespace seal;
using namespace std;

template<class T>
py::tuple serialize(T &c) {
    std::stringstream output(std::ios::binary | std::ios::out);
    c.save(output);
    auto cipherstr = output.str();
    auto base64_encoded_cipher = base64_encode(reinterpret_cast<const unsigned char *>(cipherstr.c_str()),
                                               cipherstr.length());
    return py::make_tuple(base64_encoded_cipher);
}

template<class T>
T deserialize(py::tuple t) {
    if (t.size() != 1)
        throw std::runtime_error("(Pickle) Invalid input tuple!");
    T c = T();
    auto cipherstr_encoded = t[0].cast<std::string>();
    auto cipherstr_decoded = base64_decode(cipherstr_encoded);
    std::stringstream input(std::ios::binary | std::ios::in);
    input.str(cipherstr_decoded);

    c.load(input);
    return c;
}

// Work around to bind MemoryManager function
static inline MemoryPoolHandle GetPool() {
    return MemoryManager::GetPool();
}

PYBIND11_MAKE_OPAQUE(std::vector<int>);
PYBIND11_MAKE_OPAQUE(std::vector<uint64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<int64_t>);
PYBIND11_MAKE_OPAQUE(std::vector<double>);
PYBIND11_MAKE_OPAQUE(std::vector<std::complex<double>>);

PYBIND11_MODULE(seal_wrapper, m) {
    // Rebind stl containers to enable pass by reference returning values
    py::bind_vector<std::vector<int>>(m, "VectorInt")
            .def("reserve", &std::vector<int>::reserve);
    py::bind_vector<std::vector<uint64_t>>(m, "VectorUInt64")
            .def("reserve", &std::vector<uint64_t>::reserve);
    py::bind_vector<std::vector<int64_t>>(m, "VectorInt64")
            .def("reserve", &std::vector<int64_t>::reserve);
    py::bind_vector<std::vector<double>>(m, "VectorDouble")
            .def("reserve", &std::vector<double>::reserve);
    py::bind_vector<std::vector<std::complex<double>>>(m, "VectorComplexDouble")
            .def("reserve", &std::vector<std::complex<double>>::reserve);

    // MemoryPoolHandle
    py::class_<MemoryPoolHandle>(m, "MemoryPoolHandle")
            .def(py::init<>())
            .def(py::init<const MemoryPoolHandle>(), py::arg("pool"))
            .def_static("New", &MemoryPoolHandle::New, py::arg("clear_on_destruction") = false,
                        "Returns a MemoryPoolHandle pointing to a new memory pool")
            .def_static("acquire_global", &MemoryPoolHandle::Global,
                        "Returns a MemoryPoolHandle pointing to the global memory pool")
            .def_static("GetPool", &GetPool,
                        "Returns the default memory pool from the MemoryManager.");

    // BatchEncoder
    py::class_<BatchEncoder>(m, "BatchEncoder")
            .def(py::init<std::shared_ptr<SEALContext> &>(), py::arg("context"))
            .def("encode",
                 (void (BatchEncoder::*)
                         (const std::vector<std::uint64_t> &,
                          Plaintext &)) &BatchEncoder::encode,
                 py::arg("values"), py::arg("destination"))
            .def("encode",
                 (void (BatchEncoder::*)
                         (const std::vector<std::int64_t> &,
                          Plaintext &)) &BatchEncoder::encode,
                 py::arg("values"), py::arg("destination"))
            .def("encode",
                 (void (BatchEncoder::*)(Plaintext &, const MemoryPoolHandle)) &BatchEncoder::encode,
                 py::arg("plain"), py::arg("pool") = GetPool())
            .def("decode",
                 (void (BatchEncoder::*)(const Plaintext &,
                                         std::vector<std::uint64_t> &,
                                         const MemoryPoolHandle)) &BatchEncoder::decode,
                 py::arg("plain"), py::arg("destination"),
                 py::arg("pool") = GetPool())
            .def("decode",
                 (void (BatchEncoder::*)(const Plaintext &,
                                         std::vector<std::int64_t> &,
                                         const MemoryPoolHandle)) &BatchEncoder::decode,
                 py::arg("plain"), py::arg("destination"),
                 py::arg("pool") = GetPool())
            .def("decode",
                 (void (BatchEncoder::*)(Plaintext &,
                                         const MemoryPoolHandle)) &BatchEncoder::decode,
                 py::arg("plain"), py::arg("pool") = GetPool())
            .def("slot_count", &BatchEncoder::slot_count, "Returns the total number of batching slots");

    // BigUInt
    py::class_<BigUInt>(m, "BigUInt")
            .def(py::init<>())
            .def("to_double", &BigUInt::to_double,
                 "Returns the BigUInt value as a double. Note that precision may be lost during the conversion.")
            .def("significant_bit_count", (int (BigUInt::*)()) &BigUInt::significant_bit_count,
                 "Returns the value of the current SmallModulus");

    // Ciphertext
    py::class_<Ciphertext>(m, "Ciphertext")
            .def(py::init<const MemoryPoolHandle>(),
                 py::arg("pool") = GetPool())
            .def(py::init<const Ciphertext &>(),
                 py::arg("ciphertext"))
            .def(py::init<const std::shared_ptr<SEALContext>>(),
                 py::arg("context"))
            .def(py::init<const std::shared_ptr<SEALContext>, const MemoryPoolHandle>(),
                 py::arg("context"), py::arg("pool") = GetPool())
            .def(py::init<std::shared_ptr<SEALContext>,
                         parms_id_type, Ciphertext::size_type,
                         MemoryPoolHandle>(),
                 py::arg("context"),
                 py::arg("parms_id"),
                 py::arg("size_capacity"),
                 py::arg("pool") = GetPool(),
                 "Constructs an empty ciphertext with given capacity. In addition to the capacity, the allocation size is determined by the given encryption parameters.")
            .def("reserve", (void (Ciphertext::*)(std::shared_ptr<SEALContext>,
                                                  parms_id_type,
                                                  Ciphertext::size_type)) &Ciphertext::reserve,
                 py::arg("context"), py::arg("parms_id"), py::arg("size_capacity"),
                 "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
            .def("reserve", (void (Ciphertext::*)(std::shared_ptr<SEALContext>,
                                                  Ciphertext::size_type)) &Ciphertext::reserve,
                 py::arg("context"), py::arg("size_capacity"),
                 "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
            .def("reserve", (void (Ciphertext::*)(Ciphertext::size_type)) &Ciphertext::reserve,
                 py::arg("size_capacity"),
                 "Allocates enough memory to accommodate the backing array of a ciphertext with given capacity")
            .def("resize", (void (Ciphertext::*)(std::shared_ptr<SEALContext>,
                                                 parms_id_type,
                                                 Ciphertext::size_type)) &Ciphertext::resize,
                 py::arg("context"), py::arg("parms_id"), py::arg("size_type"),
                 "Resizes the ciphertext to given size")
            .def("resize", (void (Ciphertext::*)(std::shared_ptr<SEALContext>,
                                                 Ciphertext::size_type)) &Ciphertext::resize,
                 py::arg("context"), py::arg("size_capacity"),
                 "Resizes the ciphertext to given size")
            .def("resize", (void (Ciphertext::*)(Ciphertext::size_type)) &Ciphertext::resize,
                 py::arg("size_capacity"),
                 "Resizes the ciphertext to given size")
            .def("release", (void (Ciphertext::*)()) &Ciphertext::release,
                 "Resets the ciphertext.")
            .def("is_valid_for", (bool (Ciphertext::*)(shared_ptr<SEALContext>)) &Ciphertext::is_valid_for,
                 "Check whether the current ciphertext is valid for a given SEALContext.")
            .def("size", &Ciphertext::size, "Returns the capacity of the allocation")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (Ciphertext::*)()) &Ciphertext::parms_id, "Get the parms_id of this object")
            .def("save", (void (Ciphertext::*)(std::string &)) &Ciphertext::python_save,
                 py::arg("path"),
                 "Saves Ciphertext object to file given filepath")
            .def("load", (void (Ciphertext::*)(std::shared_ptr<SEALContext>, std::string &)) &Ciphertext::python_load,
                 py::arg("context"), py::arg("path"),
                 "Loads Ciphertext object from file given filepath")
            .def("load", (void (Ciphertext::*)(std::string &)) &Ciphertext::python_load,
                 py::arg("path"),
                 "Loads Ciphertext object from file given filepath")
            .def("scale", (double &(Ciphertext::*)()) &Ciphertext::scale, "Get the scale of this object")
            .def(py::pickle(&serialize<Ciphertext>, &deserialize<Ciphertext>));

    // CKKS
    py::class_<CKKSEncoder>(m, "CKKSEncoder")
            .def(py::init<const std::shared_ptr<SEALContext>>())
            .def("encode", (void (CKKSEncoder::*)(const std::vector<double> &,
                                                  parms_id_type, double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("parms_id"), py::arg("scale"), py::arg("plaintext"),
                 py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &,
                                                  parms_id_type, double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("parms_id"), py::arg("scale"), py::arg("plaintext"),
                 py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(const std::vector<double> &,
                                                  double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("scale"), py::arg("plaintext"), py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(const std::vector<std::complex<double>> &,
                                                  double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("scale"), py::arg("plaintext"), py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(double, parms_id_type,
                                                  double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("value"), py::arg("parms_id"), py::arg("scale"), py::arg("plaintext"),
                 py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(double,
                                                  double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("value"), py::arg("scale"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(std::complex<double>,
                                                  parms_id_type, double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("parms_id"), py::arg("scale"), py::arg("destination"),
                 py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(std::complex<double>,
                                                  double, Plaintext &,
                                                  MemoryPoolHandle)) &CKKSEncoder::encode,
                 py::arg("values"), py::arg("scale"), py::arg("destination"),
                 py::arg("pool") = GetPool(),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(std::int64_t,
                                                  parms_id_type, Plaintext &)) &CKKSEncoder::encode,
                 py::arg("value"), py::arg("parms_id"), py::arg("destination"),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("encode", (void (CKKSEncoder::*)(std::int64_t, Plaintext &)) &CKKSEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes double-precision floating-point real or complex numbers into a plaintext polynomial.")
            .def("decode", (void (CKKSEncoder::*)(const Plaintext &,
                                                  std::vector<double> &,
                                                  MemoryPoolHandle)) &CKKSEncoder::decode,
                 py::arg("value"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Decodes a plaintext polynomial into double-precision floating-point real or complex numbers.")
            .def("decode", (void (CKKSEncoder::*)(const Plaintext &,
                                                  std::vector<std::complex<double>> &,
                                                  MemoryPoolHandle)) &CKKSEncoder::decode,
                 py::arg("value"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Decodes a plaintext polynomial into double-precision floating-point real or complex numbers.")
            .def("slot_count", &CKKSEncoder::slot_count, "Returns the total number of CKKS encoder slots");

    // Context
    py::class_<EncryptionParameterQualifiers>(m, "EncryptionParameterQualifiers");

    py::class_<SEALContext, std::shared_ptr<SEALContext>>(m, "SEALContext")
            .def_static("create", &SEALContext::Create,
                        py::arg("encryption_params"), py::arg("expand_mod_chain") = true,
                        "Creates an instance of SEALContext, and performs several pre-computations on the given EncryptionParameters.")
            .def("parms", (const EncryptionParameters &(SEALContext::*)()) &SEALContext::ContextData::parms,
                 "Returns a constant reference to the underlying encryption parameters")
            .def("parameters_set", (bool (SEALContext::*)()) &SEALContext::parameters_set,
                 "Returns whether the encryption parameters are valid.")
            .def("qualifiers", (EncryptionParameterQualifiers (SEALContext::*)()) &SEALContext::ContextData::qualifiers,
                 "Returns a copy of EncryptionParameterQualifiers corresponding to the current encryption parameters")
            .def("total_coeff_modulus_bit_count", (int (SEALContext::*)())
                    &SEALContext::ContextData::total_coeff_modulus_bit_count)
            .def(py::pickle(
                    [](const SEALContext &context) {
                        auto parms_ = context.context_data()->parms();
                        return serialize<EncryptionParameters>(parms_);
                    },
                    [](py::tuple t) {
                        /* Create a new C++ instance */
                        auto parms_ = deserialize<EncryptionParameters>(t);
                        auto context = SEALContext::Create(parms_);
                        return context;
                    }
            ));

    // Decryptor
    py::class_<Decryptor>(m, "Decryptor")
            .def(py::init<const std::shared_ptr<SEALContext>, const SecretKey &>())
            .def("decrypt", (void (Decryptor::*)(const Ciphertext &, Plaintext &)) &Decryptor::decrypt,
                 py::arg("encrypted"), py::arg("destination"),
                 "Decrypts a ciphertext and writes the result to a given destination.")
            .def("invariant_noise_budget", (int (Decryptor::*)(const Ciphertext &))
                         &Decryptor::invariant_noise_budget,
                 py::arg("encrypted"),
                 "Returns noise budget");

    // defaultparams
    m.def("coeff_modulus_128", &coeff_modulus_128,
          py::arg("poly_modulus_degree"),
          "Returns the default coefficients modulus for a given polynomial modulus degree.")
            .def("coeff_modulus_192", &coeff_modulus_192,
                 py::arg("poly_modulus_degree"),
                 "Returns the default coefficients modulus for a given polynomial modulus degree.")
            .def("coeff_modulus_256", &coeff_modulus_256,
                 py::arg("poly_modulus_degree"),
                 "Returns the default coefficients modulus for a given polynomial modulus degree.")
            .def("small_mods_60bit", &small_mods_60bit,
                 py::arg("index"), "Returns a 60-bit coefficient modulus prime.")
            .def("small_mods_50bit", &small_mods_50bit,
                 py::arg("index"), "Returns a 50-bit coefficient modulus prime.")
            .def("small_mods_40bit", &small_mods_40bit,
                 py::arg("index"), "Returns a 40-bit coefficient modulus prime.")
            .def("small_mods_30bit", &small_mods_30bit,
                 py::arg("index"), "Returns a 30-bit coefficient modulus prime.")
            .def("dbc_max", &dbc_max, "Returns the largest allowed decomposition bit count")
            .def("dbc_min", &dbc_min, "Returns the smallest allowed decomposition bit count");

    // Encoder
    py::class_<BinaryEncoder>(m, "BinaryEncoder")
            .def(py::init<const SmallModulus &>(),
                 py::arg("plain_modulus"))
            .def("encode", (Plaintext (BinaryEncoder::*)(std::uint64_t)) &BinaryEncoder::encode,
                 py::arg("value"),
                 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.")
            .def("encode", (void (BinaryEncoder::*)(std::uint64_t, Plaintext &)) &BinaryEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BinaryEncoder::*)(std::int64_t)) &BinaryEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.")
            .def("encode", (void (BinaryEncoder::*)(std::int64_t, Plaintext &)) &BinaryEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BinaryEncoder::*)(const BigUInt &)) &BinaryEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by BigUInt) into a plaintext polynomial.")
            .def("encode", (void (BinaryEncoder::*)(const BigUInt &, Plaintext &)) &BinaryEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by BigUInt) into a plaintext polynomial.")
            .def("encode", (Plaintext (BinaryEncoder::*)(std::int32_t)) &BinaryEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.")
            .def("encode", (void (BinaryEncoder::*)(std::int32_t, Plaintext &)) &BinaryEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BinaryEncoder::*)(std::uint32_t)) &BinaryEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::uint32_t) into a plaintext polynomial.")
            .def("encode", (void (BinaryEncoder::*)(std::uint32_t, Plaintext &)) &BinaryEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::uint32_t) into a plaintext polynomial.")
            .def("decode_uint32", (std::uint32_t (BinaryEncoder::*)(const Plaintext &)) &BinaryEncoder::decode_uint32,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::uint32_t.")
            .def("decode_uint64", (std::uint64_t (BinaryEncoder::*)(const Plaintext &)) &BinaryEncoder::decode_uint64,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::uint64_t.")
            .def("decode_int32", (std::int32_t (BinaryEncoder::*)(const Plaintext &)) &BinaryEncoder::decode_int32,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::int32_t.")
            .def("decode_int64", (std::int64_t (BinaryEncoder::*)(const Plaintext &)) &BinaryEncoder::decode_int64,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::int64_t.")
            .def("decode_biguint", (BigUInt (BinaryEncoder::*)(const Plaintext &)) &BinaryEncoder::decode_biguint,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as BigUInt")
            .def("decode_biguint",
                 (void (BinaryEncoder::*)(const Plaintext &, BigUInt &)) &BinaryEncoder::decode_biguint,
                 py::arg("plain"), py::arg("destination"),
                 "Decodes a plaintext polynomial and returns the result as BigUInt");

    py::class_<BalancedEncoder>(m, "BalancedEncoder")
            .def(py::init<const SmallModulus &, std::uint64_t>(), py::arg("plain_modulus"), py::arg("base") = 3)
            .def("encode", (Plaintext (BalancedEncoder::*)(std::uint64_t)) &BalancedEncoder::encode,
                 py::arg("value"),
                 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.")
            .def("encode", (void (BalancedEncoder::*)(std::uint64_t, Plaintext &)) &BalancedEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes an unsigned integer (represented by std::uint64_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BalancedEncoder::*)(std::int64_t)) &BalancedEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.")
            .def("encode", (void (BalancedEncoder::*)(std::int64_t, Plaintext &)) &BalancedEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::int64_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BalancedEncoder::*)(const BigUInt &)) &BalancedEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by BigUInt) into a plaintext polynomial.")
            .def("encode", (void (BalancedEncoder::*)(const BigUInt &, Plaintext &)) &BalancedEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by BigUInt) into a plaintext polynomial.")
            .def("encode", (Plaintext (BalancedEncoder::*)(std::int32_t)) &BalancedEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.")
            .def("encode", (void (BalancedEncoder::*)(std::int32_t, Plaintext &)) &BalancedEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::int32_t) into a plaintext polynomial.")
            .def("encode", (Plaintext (BalancedEncoder::*)(std::uint32_t)) &BalancedEncoder::encode,
                 py::arg("value"),
                 "Encodes a signed integer (represented by std::uint32_t) into a plaintext polynomial.")
            .def("encode", (void (BalancedEncoder::*)(std::uint32_t, Plaintext &)) &BalancedEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encodes a signed integer (represented by std::uint32_t) into a plaintext polynomial.")
            .def("decode_uint32",
                 (std::uint32_t (BalancedEncoder::*)(const Plaintext &)) &BalancedEncoder::decode_uint32,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::uint32_t.")
            .def("decode_uint64",
                 (std::uint64_t (BalancedEncoder::*)(const Plaintext &)) &BalancedEncoder::decode_uint64,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::uint64_t.")
            .def("decode_int32", (std::int32_t (BalancedEncoder::*)(const Plaintext &)) &BalancedEncoder::decode_int32,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::int32_t.")
            .def("decode_int64", (std::int64_t (BalancedEncoder::*)(const Plaintext &)) &BalancedEncoder::decode_int64,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as std::int64_t.")
            .def("decode_biguint", (BigUInt (BalancedEncoder::*)(const Plaintext &)) &BalancedEncoder::decode_biguint,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as BigUInt")
            .def("decode_biguint",
                 (void (BalancedEncoder::*)(const Plaintext &, BigUInt &)) &BalancedEncoder::decode_biguint,
                 py::arg("plain"), py::arg("destination"),
                 "Decodes a plaintext polynomial and returns the result as BigUInt");

    py::class_<BinaryFractionalEncoder>(m, "BinaryFractionalEncoder")
            .def(py::init<const SmallModulus &, std::size_t, std::size_t, std::size_t>(),
                 py::arg("plain_modulus"),
                 py::arg("poly_modulus_degree"),
                 py::arg("integer_coeff_count"),
                 py::arg("fraction_coeff_count"))
            .def("encode", (Plaintext (BinaryFractionalEncoder::*)(double)) &BinaryFractionalEncoder::encode,
                 py::arg("value"),
                 "Encodes a double precision floating point number into a plaintext polynomial")
            .def("decode", (double (BinaryFractionalEncoder::*)(const Plaintext &)) &BinaryFractionalEncoder::decode,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as a double-precision floating-point number")
            .def("poly_modulus_degree",
                 (std::size_t (BinaryFractionalEncoder::*)()) &BinaryFractionalEncoder::poly_modulus_degree)
            .def("fraction_coeff_count",
                 (std::size_t (BinaryFractionalEncoder::*)()) &BinaryFractionalEncoder::fraction_coeff_count)
            .def("integer_coeff_count",
                 (std::size_t (BinaryFractionalEncoder::*)()) &BinaryFractionalEncoder::integer_coeff_count)
            .def("base",
                 (std::uint64_t (BinaryFractionalEncoder::*)()) &BinaryFractionalEncoder::base);

    py::class_<BalancedFractionalEncoder>(m, "BalancedFractionalEncoder")
            .def(py::init<const SmallModulus &, std::size_t,
                         std::size_t, std::size_t, std::uint64_t>(),
                 py::arg("plain_modulus"),
                 py::arg("poly_modulus_degree"),
                 py::arg("integer_coeff_count"),
                 py::arg("fraction_coeff_count"),
                 py::arg("base") = 3)
            .def("encode", (Plaintext (BalancedFractionalEncoder::*)(double)) &BalancedFractionalEncoder::encode,
                 py::arg("value"),
                 "Encodes a double precision floating point number into a plaintext polynomial")
            .def("decode",
                 (double (BalancedFractionalEncoder::*)(const Plaintext &)) &BalancedFractionalEncoder::decode,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as a double-precision floating-point number")
            .def("poly_modulus_degree",
                 (std::size_t (BalancedFractionalEncoder::*)()) &BalancedFractionalEncoder::poly_modulus_degree)
            .def("fraction_coeff_count",
                 (std::size_t (BalancedFractionalEncoder::*)()) &BalancedFractionalEncoder::fraction_coeff_count)
            .def("integer_coeff_count",
                 (std::size_t (BalancedFractionalEncoder::*)()) &BalancedFractionalEncoder::integer_coeff_count)
            .def("base",
                 (std::uint64_t (BalancedFractionalEncoder::*)()) &BalancedFractionalEncoder::base);

    py::class_<IntegerEncoder>(m, "IntegerEncoder")
            .def(py::init<const SmallModulus &>(), py::arg("plain_modulus"))
            .def(py::init<const SmallModulus &, std::uint64_t>(), py::arg("plain_modulus"), py::arg("base") = 2)
            .def("encode", (Plaintext (IntegerEncoder::*)(std::uint64_t)) &IntegerEncoder::encode,
                 py::arg("value"),
                 "Encode integer")
            .def("encode", (void (IntegerEncoder::*)(std::uint64_t, Plaintext &)) &IntegerEncoder::encode,
                 "Encode integer and store in given destination")
            .def("encode", (Plaintext (IntegerEncoder::*)(std::int64_t)) &IntegerEncoder::encode,
                 py::arg("value"),
                 "Encode integer")
            .def("encode", (void (IntegerEncoder::*)(std::int64_t, Plaintext &)) &IntegerEncoder::encode,
                 "Encode integer and store in given destination")
            .def("encode", (Plaintext (IntegerEncoder::*)(const BigUInt &)) &IntegerEncoder::encode,
                 py::arg("value"),
                 "Encode integer")
            .def("encode", (void (IntegerEncoder::*)(const BigUInt &, Plaintext &)) &IntegerEncoder::encode,
                 "Encode integer and store in given destination")
            .def("encode", (Plaintext (IntegerEncoder::*)(std::int32_t)) &IntegerEncoder::encode,
                 py::arg("value"),
                 "Encode integer")
            .def("encode", (Plaintext (IntegerEncoder::*)(std::uint32_t)) &IntegerEncoder::encode,
                 py::arg("value"),
                 "Encode integer")
            .def("encode", (void (IntegerEncoder::*)(std::int32_t, Plaintext &)) &IntegerEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encode integer and store in given destination")
            .def("encode", (void (IntegerEncoder::*)(std::uint32_t, Plaintext &)) &IntegerEncoder::encode,
                 py::arg("value"), py::arg("destination"),
                 "Encode integer and store in given destination")
            .def("decode_biguint",
                 (void (IntegerEncoder::*)(const Plaintext &, BigUInt &)) &IntegerEncoder::decode_biguint,
                 py::arg("plain"), py::arg("destination"),
                 "Decode a plaintext polynomial and store in a given destination")
            .def("decode_biguint", (BigUInt (IntegerEncoder::*)(const Plaintext &)) &IntegerEncoder::decode_biguint,
                 py::arg("plain"),
                 "Decode a plaintext polynomial")
            .def("decode_int64", (std::int64_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_int64,
                 py::arg("plain"),
                 "Decode a plaintext polynomial")
            .def("decode_int32", (std::int32_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_int32,
                 py::arg("plain"),
                 "Decode a plaintext polynomial")
            .def("decode_uint64", (std::uint64_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_uint64,
                 py::arg("plain"),
                 "Decode a plaintext polynomial")
            .def("decode_uint32", (std::uint32_t (IntegerEncoder::*)(Plaintext &)) &IntegerEncoder::decode_uint32,
                 py::arg("plain"),
                 "Decode a plaintext polynomial");

    py::class_<FractionalEncoder>(m, "FractionalEncoder")
            .def(py::init<const SmallModulus &, std::size_t,
                         std::size_t, std::size_t, uint64_t>(),
                 py::arg("plain_modulus"),
                 py::arg("poly_modulus_degree"),
                 py::arg("integer_coeff_count"),
                 py::arg("fraction_coeff_count"),
                 py::arg("base") = 2)
            .def(py::init<const FractionalEncoder &>())
            .def("encode", (Plaintext (FractionalEncoder::*)(double)) &FractionalEncoder::encode,
                 py::arg("value"),
                 "Encodes a double precision floating point number into a plaintext polynomial")
            .def("decode", (double (FractionalEncoder::*)(const Plaintext &)) &FractionalEncoder::decode,
                 py::arg("plain"),
                 "Decodes a plaintext polynomial and returns the result as a double-precision floating-point number");

    // EncryptionParameters
    py::class_<EncryptionParameters>(m, "EncryptionParameters")
            .def(py::init<>())
            .def(py::init<scheme_type>(), py::arg("scheme_type"))
            .def(py::init<const EncryptionParameters &>())
            .def("set_poly_modulus",
                 (void (EncryptionParameters::*)(const std::size_t)) &EncryptionParameters::set_poly_modulus_degree,
                 py::arg("poly_modulus_degree"),
                 "Set polynomial modulus parameter")
            .def("poly_modulus_degree", &EncryptionParameters::poly_modulus_degree,
                 "Get the polynomial modulus degree")
            .def("set_coeff_modulus",
                 (void (EncryptionParameters::*)(
                         const std::vector<SmallModulus> &)) &EncryptionParameters::set_coeff_modulus,
                 py::arg("coeff_modulus"),
                 "Set coefficient modulus parameter")
            .def("coeff_modulus", &EncryptionParameters::coeff_modulus,
                 "Get the coeff modulus")
            .def("set_plain_modulus",
                 (void (EncryptionParameters::*)(const SmallModulus &)) &EncryptionParameters::set_plain_modulus,
                 py::arg("plain_modulus"),
                 "Set plaintext modulus parameter")
            .def("set_plain_modulus",
                 (void (EncryptionParameters::*)(std::uint64_t)) &EncryptionParameters::set_plain_modulus,
                 py::arg("plain_modulus"),
                 "Set plaintext modulus parameter")
            .def("plain_modulus", &EncryptionParameters::plain_modulus, "Returns the plaintext modulus")
            .def("set_noise_standard_deviation",
                 (void (EncryptionParameters::*)(double)) &EncryptionParameters::set_noise_standard_deviation,
                 py::arg("noise_standard_deviation"),
                 "Sets the standard deviation of the noise distribution used for error sampling. This parameter directly affects the security level of the scheme.")
            .def("set_random_generator",
                 (void (EncryptionParameters::*)(
                         std::shared_ptr<FastPRNGFactory>)) &EncryptionParameters::set_random_generator,
                 py::arg("random_generator"),
                 "Sets the random number generator factory to use for encryption.")
            .def("scheme_type",
                 (scheme_type (EncryptionParameters::*)()) &EncryptionParameters::scheme,
                 "Returns the encryption scheme type.")
            .def("poly_modulus_degree",
                 (std::size_t (EncryptionParameters::*)()) &EncryptionParameters::poly_modulus_degree,
                 "Returns the degree of the polynomial modulus parameter.")
            .def("noise_standard_deviation",
                 (double (EncryptionParameters::*)()) &EncryptionParameters::noise_standard_deviation,
                 "Returns the currently set standard deviation of the noise distribution.")
            .def("noise_max_deviation",
                 (double (EncryptionParameters::*)()) &EncryptionParameters::noise_max_deviation,
                 "Returns the currently set maximum deviation of the noise distribution.")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (EncryptionParameters::*)()) &EncryptionParameters::parms_id, "Get the parms_id of this object")
            .def(py::pickle(&serialize<EncryptionParameters>, &deserialize<EncryptionParameters>));

    // Encryptor
    py::class_<Encryptor>(m, "Encryptor")
            .def(py::init<const std::shared_ptr<SEALContext>, const PublicKey &>(),
                 py::arg("context"), py::arg("public_key"))
            .def("encrypt",
                 (void (Encryptor::*)(const Plaintext &, Ciphertext &, MemoryPoolHandle)) &Encryptor::encrypt,
                 py::arg("plain"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Encrypts a plaintext and writes the result to a given destination");

    // Evaluator
    py::enum_<scheme_type>(m, "scheme_type")
            .value("BFV", scheme_type::BFV)
            .value("CKKS", scheme_type::CKKS);

    py::class_<Evaluator>(m, "Evaluator")
            .def(py::init<const std::shared_ptr<SEALContext>>(), py::arg("context"))
            .def("negate", (void (Evaluator::*)(Ciphertext &)) &Evaluator::negate_inplace,
                 py::arg("ciphertext"),
                 "Negates a ciphertext")
            .def("negate", (void (Evaluator::*)(const Ciphertext &, Ciphertext &)) &Evaluator::negate,
                 py::arg("ciphertext"), py::arg("destination"),
                 "Negates a ciphertext and writes to a given destination")
            .def("add", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
                                             Ciphertext &)) &Evaluator::add,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("destination"),
                 "Adds two ciphertexts and writes to a given destination")
            .def("add", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) &Evaluator::add_inplace,
                 py::arg("encrypted1"), py::arg("encrypted2"),
                 "Adds two ciphertexts and writes output over the first ciphertext")
            .def("add_many", (void (Evaluator::*)(const std::vector<Ciphertext> &, Ciphertext &)) &Evaluator::add_many,
                 py::arg("encrypted_array"), py::arg("destination"),
                 "Adds together a vector of ciphertexts and stores the result in the destination parameter.")
            .def("sub", (void (Evaluator::*)(Ciphertext &, const Ciphertext &)) &Evaluator::sub_inplace,
                 py::arg("encrypted1"), py::arg("encrypted2"),
                 "Subtracts two ciphertexts and writes output over the first ciphertext")
            .def("sub", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
                                             Ciphertext &)) &Evaluator::sub,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("destination"),
                 "Subtracts two ciphertexts and writes to a given destination")
            .def("multiply", (void (Evaluator::*)(Ciphertext &, const Ciphertext &,
                                                  MemoryPoolHandle)) &Evaluator::multiply_inplace,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("pool") = GetPool(),
                 "Multiplies two ciphertexts and writes output over the first ciphertext")
            .def("multiply", (void (Evaluator::*)(const Ciphertext &, const Ciphertext &,
                                                  Ciphertext &, MemoryPoolHandle)) &Evaluator::multiply,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Multiplies two ciphertexts and writes to a given destination")
            .def("square", (void (Evaluator::*)(Ciphertext &, MemoryPoolHandle)) &Evaluator::square_inplace,
                 py::arg("encrypted"), py::arg("pool") = GetPool(),
                 "Squares a ciphertext")
            .def("square", (void (Evaluator::*)(Ciphertext &, Ciphertext &, MemoryPoolHandle)) &Evaluator::square,
                 py::arg("encrypted"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Squares a ciphertext")
            .def("relinearize", (void (Evaluator::*)(Ciphertext &, const RelinKeys &, MemoryPoolHandle))
                         &Evaluator::relinearize_inplace,
                 py::arg("encrypted"), py::arg("relin_keys"), py::arg("pool") = GetPool(), "Relinearizes a ciphertext")
            .def("relinearize", (void (Evaluator::*)(const Ciphertext &, const RelinKeys &,
                                                     Ciphertext &, MemoryPoolHandle)) &Evaluator::relinearize,
                 py::arg("encrypted"), py::arg("relin_keys"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Relinearizes a ciphertext and writes to a given destination")
            .def("multiply_many", (void (Evaluator::*)(std::vector<Ciphertext> &,
                                                       const RelinKeys &, Ciphertext &,
                                                       MemoryPoolHandle)) &Evaluator::multiply_many,
                 py::arg("encrypteds"), py::arg("relin_keys"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Multiplies two ciphertexts and writes to a given destination")
            .def("exponentiate", (void (Evaluator::*)(Ciphertext &, std::uint64_t,
                                                      const RelinKeys &, MemoryPoolHandle))
                         &Evaluator::exponentiate_inplace,
                 py::arg("ciphertext"), py::arg("exponent"), py::arg("relin_keys"), py::arg("pool") = GetPool(),
                 "Exponentiates a ciphertext.")
            .def("exponentiate", (void (Evaluator::*)(const Ciphertext &, std::uint64_t,
                                                      const RelinKeys &, Ciphertext &, MemoryPoolHandle))
                         &Evaluator::exponentiate,
                 py::arg("ciphertext"), py::arg("exponent"), py::arg("relin_keys"), py::arg("destination"),
                 py::arg("pool") = GetPool(),
                 "Exponentiates a ciphertext.")
            .def("add_plain", (void (Evaluator::*)(Ciphertext &, const Plaintext &)) &Evaluator::add_plain_inplace,
                 py::arg("ciphertext"), py::arg("plain"),
                 "Adds a ciphertext and a plaintext.")
            .def("add_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &))
                         &Evaluator::add_plain,
                 py::arg("ciphertext"), py::arg("plain"), py::arg("destination"),
                 "Adds a ciphertext and a plaintext, placing result in destination.")
            .def("sub_plain", (void (Evaluator::*)(Ciphertext &, const Plaintext &))
                         &Evaluator::sub_plain_inplace,
                 py::arg("ciphertext"), py::arg("plain"),
                 "Subtracts a plaintext from a ciphertext.")
            .def("sub_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &, Ciphertext &))
                         &Evaluator::sub_plain,
                 py::arg("ciphertext"), py::arg("plain"), py::arg("destination"),
                 "Subtracts a plaintext from a ciphertext.")
            .def("multiply_plain", (void (Evaluator::*)(Ciphertext &, const Plaintext &, MemoryPoolHandle))
                         &Evaluator::multiply_plain_inplace,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("pool") = GetPool(),
                 "Multiplies a ciphertext with a plaintext")
            .def("multiply_plain", (void (Evaluator::*)(const Ciphertext &, const Plaintext &,
                                                        Ciphertext &, MemoryPoolHandle)) &Evaluator::multiply_plain,
                 py::arg("encrypted1"), py::arg("encrypted2"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Multiplies a ciphertext with a plaintext and writes to a given destination")
            .def("rotate_rows", (void (Evaluator::*)(const Ciphertext &, int,
                                                     const GaloisKeys &, Ciphertext &,
                                                     MemoryPoolHandle)) &Evaluator::rotate_rows,
                 py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("destination"),
                 py::arg("pool") = GetPool(),
                 "Rotates plaintext matrix rows cyclically")
            .def("rotate_rows", (void (Evaluator::*)(Ciphertext &, int,
                                                     const GaloisKeys &,
                                                     MemoryPoolHandle)) &Evaluator::rotate_rows_inplace,
                 py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("pool") = GetPool(),
                 "Rotates plaintext matrix rows cyclically")
            .def("rotate_columns", (void (Evaluator::*)(Ciphertext &,
                                                        const GaloisKeys &,
                                                        MemoryPoolHandle)) &Evaluator::rotate_columns_inplace,
                 py::arg("encrypted"), py::arg("galois_keys"), py::arg("pool") = GetPool(),
                 "Rotates plaintext matrix rows cyclically")
            .def("rotate_columns", (void (Evaluator::*)(const Ciphertext &, const GaloisKeys &,
                                                        Ciphertext &,
                                                        MemoryPoolHandle)) &Evaluator::rotate_columns,
                 py::arg("encrypted"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Rotates plaintext matrix rows cyclically")
            .def("rotate_vector", (void (Evaluator::*)(const Ciphertext &, int,
                                                       const GaloisKeys &, MemoryPoolHandle))
                         &Evaluator::rotate_vector_inplace,
                 py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("pool") = GetPool(),
                 "Rotates plaintext vector cyclically.")
            .def("rotate_vector", (void (Evaluator::*)(const Ciphertext &, int,
                                                       const GaloisKeys &, Ciphertext &,
                                                       MemoryPoolHandle)) &Evaluator::rotate_vector,
                 py::arg("encrypted"), py::arg("steps"), py::arg("galois_keys"), py::arg("destination"),
                 py::arg("pool") = GetPool(),
                 "Rotates plaintext vector cyclically.")
            .def("complex_conjugate", (void (Evaluator::*)(const Ciphertext &,
                                                           const GaloisKeys &, MemoryPoolHandle))
                         &Evaluator::complex_conjugate_inplace,
                 py::arg("encrypted"), py::arg("galois_keys"), py::arg("pool") = GetPool(),
                 "Complex conjugates plaintext slot values.")
            .def("complex_conjugate", (void (Evaluator::*)(const Ciphertext &,
                                                           const GaloisKeys &, Ciphertext &,
                                                           MemoryPoolHandle)) &Evaluator::complex_conjugate,
                 py::arg("encrypted"), py::arg("galois_keys"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Complex conjugates plaintext slot values.")
            .def("mod_switch_to_next",
                 (void (Evaluator::*)(const Plaintext &, Plaintext &)) &Evaluator::mod_switch_to_next,
                 "Switch to the next coeff modulus")
            .def("mod_switch_to_next",
                 (void (Evaluator::*)(const Ciphertext &encrypted, Ciphertext &destination,
                                      MemoryPoolHandle)) &Evaluator::mod_switch_to_next,
                 "Switch to the next coeff modulus")
            .def("mod_switch_to_next",
                 (void (Evaluator::*)(Ciphertext &encrypted,
                                      MemoryPoolHandle)) &Evaluator::mod_switch_to_next_inplace,
                 "Switch to the next coeff modulus")
            .def("mod_switch_to_next",
                 (void (Evaluator::*)(Plaintext &plain)) &Evaluator::mod_switch_to_next_inplace,
                 "Switch to the next coeff modulus")
            .def("mod_switch_to", (void (Evaluator::*)(const Ciphertext &,
                                                       parms_id_type, Ciphertext &,
                                                       MemoryPoolHandle)) &Evaluator::mod_switch_to,
                 "Switch to a given modulus")
            .def("mod_switch_to", (void (Evaluator::*)(Ciphertext &, parms_id_type,
                                                       MemoryPoolHandle)) &Evaluator::mod_switch_to_inplace,
                 "Switch to a given modulus")
            .def("mod_switch_to",
                 (void (Evaluator::*)(Plaintext &plain, parms_id_type parms_id)) &Evaluator::mod_switch_to_inplace,
                 "Switch to a given modulus")
            .def("mod_switch_to", (void (Evaluator::*)(const Plaintext &plain, parms_id_type parms_id,
                                                       Plaintext &destination)) &Evaluator::mod_switch_to,
                 "Switch to a given modulus")
            .def("rescale_to_next", (void (Evaluator::*)(const Ciphertext &, Ciphertext &,
                                                         MemoryPoolHandle)) &Evaluator::rescale_to_next,
                 "Switch down modulus and rescale message accordingly")
            .def("rescale_to_next", (void (Evaluator::*)(Ciphertext &,
                                                         MemoryPoolHandle)) &Evaluator::rescale_to_next_inplace,
                 "Switch down modulus and rescale message accordingly")

            .def("rescale_to", (void (Evaluator::*)(const Ciphertext &,
                                                    parms_id_type, Ciphertext &,
                                                    MemoryPoolHandle)) &Evaluator::rescale_to,
                 py::arg("encrypted"), py::arg("parms_id"), py::arg("destination"), py::arg("pool") = GetPool(),
                 "Switch down modulus and rescale message accordingly")
            .def("rescale_to", (void (Evaluator::*)(Ciphertext &, parms_id_type,
                                                    MemoryPoolHandle)) &Evaluator::rescale_to_inplace,
                 py::arg("encrypted"), py::arg("parms_id"), py::arg("pool") = GetPool(),
                 "Switch down modulus and rescale message accordingly");

    // GaloisKeys
    py::class_<GaloisKeys>(m, "GaloisKeys")
            .def(py::init<>())
            .def(py::init<const GaloisKeys &>())
            .def("save", (void (GaloisKeys::*)(std::string &)) &GaloisKeys::python_save,
                 py::arg("path"),
                 "Saves GaloisKeys object to file given filepath")
            .def("load", (void (GaloisKeys::*)(std::shared_ptr<SEALContext>, std::string &)) &GaloisKeys::python_load,
                 py::arg("context"), py::arg("path"),
                 "Loads GaloisKeys object from file given SEALContext and filepath")
            .def("load", (void (GaloisKeys::*)(std::string &)) &GaloisKeys::python_load,
                 py::arg("path"),
                 "Loads GaloisKeys object from file given filepath")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (GaloisKeys::*)()) &GaloisKeys::parms_id, "Get the parms_id of this object")
            .def(py::pickle(&serialize<GaloisKeys>, &deserialize<GaloisKeys>));

    // KeyGenerator
    py::class_<KeyGenerator>(m, "KeyGenerator")
            .def(py::init<std::shared_ptr<SEALContext>>(), py::arg("context"))
            .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &>(), py::arg("context"), py::arg("secret_key"))
            .def(py::init<std::shared_ptr<SEALContext>, const SecretKey &, const PublicKey &>(),
                 py::arg("context"), py::arg("secret_key"), py::arg("public_key"))
            .def("relin_keys", (RelinKeys (KeyGenerator::*)(int, std::size_t)) &KeyGenerator::relin_keys,
                 py::arg("decomposition_bit_count"), py::arg("count") = 1,
                 "Generates and returns the specified number of relinearization keys.")
            .def("galois_keys",
                 (GaloisKeys (KeyGenerator::*)(int, const std::vector<std::uint64_t> &)) &KeyGenerator::galois_keys,
                 py::arg("decomposition_bit_count"), py::arg("galois_elts"),
                 "Generates and returns a galois keys.")
            .def("galois_keys",
                 (GaloisKeys (KeyGenerator::*)(int, const std::vector<int> &)) &KeyGenerator::galois_keys,
                 py::arg("decomposition_bit_count"), py::arg("steps"),
                 "Generates and returns a galois keys.")
            .def("galois_keys",
                 (GaloisKeys (KeyGenerator::*)(int)) &KeyGenerator::galois_keys,
                 py::arg("decomposition_bit_count"),
                 "Generates and returns a galois keys.")
            .def("public_key", &KeyGenerator::public_key, "Returns public key")
            .def("secret_key", &KeyGenerator::secret_key, "Returns secret key");

    // Plaintext
    py::class_<Plaintext>(m, "Plaintext")
            .def(py::init<>())
            .def(py::init<const Plaintext &>())
            .def(py::init<Plaintext::size_type>(), py::arg("coeff_count"))
            .def(py::init<Plaintext::size_type, Plaintext::size_type>(), py::arg("capacity"), py::arg("coeff_count"))
            .def(py::init<const std::string &>(), py::arg("hex_poly"))
            .def("significant_coeff_count", &Plaintext::significant_coeff_count,
                 "Returns the significant coefficient count of the current plaintext polynomial")
            .def("coeff_count", &Plaintext::coeff_count,
                 "Returns the coefficient count of the current plaintext polynomial")
            .def(py::pickle(&serialize<Plaintext>, &deserialize<Plaintext>))
            .def("save", (void (Plaintext::*)(std::string &)) &Plaintext::python_save, py::arg("path"),
                 "Saves Plaintext object to file given filepath")
            .def("load", (void (Plaintext::*)(std::string &)) &Plaintext::python_load, py::arg("path"),
                 "Loads Plaintext object from file given filepath")
            .def("to_string", &Plaintext::to_string, "Returns a human readable string description of the polynomial")
            .def("is_valid_for", &Plaintext::is_valid_for,
                 "Check whether the current Plaintext is valid for a given SEALContext.")
            .def("is_zero", &Plaintext::is_zero, "Checks if a plaintext is zero")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (Plaintext::*)()) &Plaintext::parms_id, "Get the parms_id of this object")
            .def("scale", (double &(Plaintext::*)()) &Plaintext::scale, "Get the scale of this object")
            .def(py::pickle(&serialize<Plaintext>, &deserialize<Plaintext>));

    // PublicKey
    py::class_<PublicKey>(m, "PublicKey")
            .def(py::init<>())
            .def(py::init<const PublicKey &>())
            .def("save", (void (PublicKey::*)(std::string &)) &PublicKey::python_save,
                 py::arg("path"),
                 "Saves PublicKey object to file given filepath")
            .def("load", (void (PublicKey::*)(std::shared_ptr<SEALContext>, std::string &)) &PublicKey::python_load,
                 py::arg("context"), py::arg("path"),
                 "Loads PublicKey object from file given SEALContext and filepath")
            .def("load", (void (PublicKey::*)(std::string &)) &PublicKey::python_load,
                 py::arg("path"),
                 "Loads PublicKey object from file given filepath")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (PublicKey::*)()) &PublicKey::parms_id, "Get the parms_id of this object")
            .def(py::pickle(&serialize<PublicKey>, &deserialize<PublicKey>));

    // RandomGenerator
    py::class_<FastPRNG, std::shared_ptr<FastPRNG>>(m, "FastPRNG")
            .def(py::init<std::uint64_t, std::uint64_t>(),
                 py::arg("low_seed"), py::arg("high_seed"),
                 "Create a FastPRNG")
            .def("generate", &FastPRNG::generate,
                 "Generate a random number using this generator.");

    py::class_<FastPRNGFactory, std::shared_ptr<FastPRNGFactory>>(m, "FastPRNGFactory")
            .def(py::init<>(),
                 "Creates a new FastPRNGFactory instance")
            .def(py::init<std::uint64_t, std::uint64_t>(),
                 py::arg("low_seed"), py::arg("high_seed"),
                 "Creates a new FastPRNGFactory instance")
            .def("create", &FastPRNGFactory::create,
                 "Creates a new FastPRNG instance");

    // RelinKeys
    py::class_<RelinKeys>(m, "RelinKeys")
            .def(py::init<>())
            .def(py::init<const RelinKeys &>())
            .def("save", (void (RelinKeys::*)(std::string &)) &RelinKeys::python_save,
                 py::arg("path"),
                 "Saves SecretKey object to file given filepath")
            .def("load", (void (RelinKeys::*)(std::shared_ptr<SEALContext>, std::string &)) &RelinKeys::python_load,
                 py::arg("context"), py::arg("path"),
                 "Loads PublicKey object from file given filepath")
            .def("load", (void (RelinKeys::*)(std::string &)) &RelinKeys::python_load,
                 py::arg("path"),
                 "Loads PublicKey object from file given filepath")
            .def("size", &RelinKeys::size, "Returns the current number of relinearization keys.")
            .def("decomposition_bit_count", &RelinKeys::decomposition_bit_count,
                 "Returns the decomposition bit count")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (RelinKeys::*)()) &RelinKeys::parms_id, "Get the parms_id of this object")
            .def(py::pickle(&serialize<RelinKeys>, &deserialize<RelinKeys>));

    // SecretKey
    py::class_<SecretKey>(m, "SecretKey")
            .def(py::init<>())
            .def(py::init<const SecretKey &>())
            .def("save", (void (SecretKey::*)(std::string &)) &SecretKey::python_save,
                 py::arg("path"),
                 "Saves SecretKey object to file given filepath")
            .def("load", (void (SecretKey::*)(std::shared_ptr<SEALContext>, std::string &)) &SecretKey::python_load,
                 py::arg("context"), py::arg("path"),
                 "Loads PublicKey object from file given filepath")
            .def("load", (void (SecretKey::*)(std::string &)) &SecretKey::python_load,
                 py::arg("path"),
                 "Loads SecretKey object from file given filepath")
            .def("parms_id", (std::array<std::uint64_t, util::HashFunction::sha3_block_uint64_count> &
            (SecretKey::*)()) &SecretKey::parms_id, "Get the parms_id of this object")
            .def(py::pickle(&serialize<SecretKey>, &deserialize<SecretKey>));

    // SmallModulus
    py::class_<SmallModulus>(m, "SmallModulus")
            .def(py::init<>())
            .def(py::init<std::uint64_t>())
            .def("value", (std::uint64_t (SmallModulus::*)()) &SmallModulus::value,
                 "Returns the value of the current SmallModulus")
            .def("bit_count", &SmallModulus::bit_count, "Returns the bit count of the small modulus")
            .def("uint64_count", &SmallModulus::uint64_count, "Returns the uint64 count of the small modulus")
            .def("is_zero", &SmallModulus::is_zero, "Check if SmallModulus is zero")
            .def(py::pickle(&serialize<SmallModulus>, &deserialize<SmallModulus>));
}