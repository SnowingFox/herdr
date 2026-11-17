#include <cstdint>

namespace v8 {
class Isolate {
 public:
  void SetStackLimit(uintptr_t stack_limit);
};
}  // namespace v8

extern "C" void rn_v8_sys__set_stack_limit(v8::Isolate* isolate,
                                            uintptr_t stack_limit) {
  isolate->SetStackLimit(stack_limit);
}
