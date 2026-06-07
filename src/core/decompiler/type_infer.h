#pragma once
#include "core/decompiler/ir.h"
#include <unordered_map>
#include <string>
#include <vector>
#include <memory>

namespace hype {

enum class DTypeKind : u8 {
    Void, Bool, Char, WChar,
    Int8, Int16, Int32, Int64,
    UInt8, UInt16, UInt32, UInt64,
    Float, Double,
    Pointer, Array, FuncPtr, Struct, SizeT
};

struct DecompType {
    DTypeKind                   kind = DTypeKind::Int64;
    std::shared_ptr<DecompType> inner;
    int                         array_count = 0;
    std::string                 struct_name;
    bool                        is_const = false;

    static DecompType make_void();
    static DecompType make_bool();
    static DecompType make_char();
    static DecompType make_int(int bits, bool sign = true);
    static DecompType make_sizet();
    static DecompType make_ptr(DecompType pointee, bool c = false);
    static DecompType make_array(DecompType inner, u32 count);
    static DecompType make_struct(std::string name);

    std::string to_string() const;
    bool is_pointer() const { return kind == DTypeKind::Pointer; }
    bool is_integer() const { return kind >= DTypeKind::Int8 && kind <= DTypeKind::UInt64; }
    int bit_width() const;
};

struct KnownFunc {
    std::string              name;
    DecompType               ret_type;
    std::vector<DecompType>  param_types;
    std::vector<std::string> param_names;
};

class TypeInfer {
public:
    void run(PcodeFunc& func);

    DecompType get_type(int var_id) const;
    std::string get_var_name(int var_id) const;
    const std::unordered_map<int, DecompType>& types() const { return types_; }
    const std::unordered_map<int, std::string>& names() const { return names_; }
    DecompType return_type() const { return ret_type_; }

    const KnownFunc* find_known(const std::string& name) const;

    enum class StlKind : u8 { None, String, Vector, SharedPtr, UniquePtr };
    StlKind detect_stl_container(int var_id, u32 struct_size, const std::vector<std::pair<i64,u32>>& accesses) const;

private:
    void init_known_funcs();
    void infer_from_ops(const PcodeFunc& func);
    void infer_from_calls(const PcodeFunc& func);
    void infer_params(const PcodeFunc& func);
    void name_variables(const PcodeFunc& func);
    void set_type(int var_id, DecompType t);

    std::unordered_map<int, DecompType>  types_;
    std::unordered_map<int, std::string> names_;
    std::vector<KnownFunc>               known_funcs_;
    DecompType                           ret_type_{DTypeKind::Int64, nullptr, 0, "", false};
};

}
