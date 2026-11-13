import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


STUBS = r'''
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)
constexpr unsigned PANDA_CAN_CNT = 3;
constexpr unsigned HEALTH_FLAG_IGNITION_LINE = 1;
constexpr unsigned HEALTH_FLAG_IGNITION_CAN = 2;
static uint64_t now_ns = 2000000000;
static bool enabled = true;
uint64_t nanos_since_boot() { return ++now_ns; }
struct Params {
  bool getBool(const char *) { return enabled; }
  std::string get(const char *) { return "configured"; }
};
namespace cereal {
struct CarParams {
  enum class SafetyModel { TOYOTA, ELM327 };
  struct SafetyConfig {
    SafetyModel getSafetyModel() const { return SafetyModel::TOYOTA; }
    uint16_t getSafetyParam() const { return 16U << 8; }
  };
  struct Fingerprint { const char *cStr() const { return "TOYOTA_CAMRY_TSS3"; } };
  std::vector<SafetyConfig> getSafetyConfigs() const { return {{}}; }
  Fingerprint getCarFingerprint() const { return {}; }
};
}
struct AlignedBuffer { int align(const char *, size_t) { return 0; } };
namespace capnp {
struct FlatArrayMessageReader {
  explicit FlatArrayMessageReader(int) {}
  template<class T> T getRoot() { return {}; }
};
}
namespace kj {
struct Exception { std::string getDescription() const { return "error"; } };
}
namespace util {
std::string hexdump(const uint8_t *data, size_t size) {
  constexpr char hex[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < size; ++i) { out += hex[data[i] >> 4]; out += hex[data[i] & 15]; }
  return out;
}
}
struct can_frame { uint32_t address; std::string dat; uint8_t src; };
struct Panda {
  struct Health { unsigned flags_pkt = 0; } health;
  std::vector<std::string> sent;
  unsigned power_calls = 0;
  Health *get_state() { return &health; }
  void set_safety_model(cereal::CarParams::SafetyModel, unsigned) {}
  void set_can_fd_auto(unsigned, bool) {}
  void can_send(uint32_t address, const std::string &data, uint8_t bus) {
    assert(address == 0x7A1 && bus == 0);
    sent.push_back(data);
  }
  void set_power_saving(bool) { ++power_calls; }
};
'''

SCENARIOS = r'''
void step(Tss3OracleStartupCatcher &catcher, Panda &panda, uint64_t ms) {
  now_ns += ms * 1000000;
  catcher.update(&panda);
}
void vehicle_rx(Tss3OracleStartupCatcher &catcher, Panda &panda) {
  catcher.process_rx(&panda, {{0x101, "vehicle", 0}});
}
void catch_programming(Tss3OracleStartupCatcher &catcher, Panda &panda) {
  const std::string positive("\x06\x50\x03\x00\x32\x01\xf4\x00", 8);
  catcher.process_rx(&panda, {{0x7A9, positive, 2}, {0x7A9, "wrong", 0}});
  assert(!catcher.caught());
  const auto before = panda.sent.size();
  catcher.process_rx(&panda, {{0x7A9, positive, 0}});
  assert(catcher.caught() && panda.sent.size() == before + 1);
  assert(panda.sent.back() == TSS3_PROGRAMMING_FRAME);
  catcher.process_rx(&panda, {{0x7A9, positive, 0}});
  assert(panda.sent.size() == before + 1);
  assert(panda.power_calls == 0);
}
int main() {
  {
    Panda panda;
    Tss3OracleStartupCatcher catcher;
    catcher.update(&panda);
    step(catcher, panda, 10000);
    assert(catcher.active() && panda.sent.empty());
    catcher.process_rx(&panda, {{0x45A, "other bus", 2}, {0x7A1, "echo", 128}, {0x7A9, "diagnostic", 0}});
    assert(panda.sent.empty());
    vehicle_rx(catcher, panda);
    assert(panda.sent.back() == TSS3_EXTENDED_FRAME);
    for (int i = 0; i < 120; ++i) {
      vehicle_rx(catcher, panda);
      const auto before = panda.sent.size();
      step(catcher, panda, 1000);
      assert(panda.sent.size() == before + 1);
    }
    catch_programming(catcher, panda);
  }
  {
    Panda panda;
    Tss3OracleStartupCatcher catcher;
    catcher.update(&panda);
    vehicle_rx(catcher, panda);
    auto before = panda.sent.size();
    now_ns += 3001000000;
    catcher.process_rx(&panda, {{0x7A9, "diagnostic", 0}, {0x7A1, "echo", 128}, {0x777, "signer", 0}});
    catcher.update(&panda);
    step(catcher, panda, 10000);
    assert(panda.sent.size() == before);
    vehicle_rx(catcher, panda);
    assert(panda.sent.size() == before + 1);
    catch_programming(catcher, panda);
  }
  {
    Panda panda;
    Tss3OracleStartupCatcher catcher;
    catcher.update(&panda);
    vehicle_rx(catcher, panda);
    panda.health.flags_pkt = HEALTH_FLAG_IGNITION_LINE;
    step(catcher, panda, 10);
    panda.health.flags_pkt = 0;
    step(catcher, panda, 100);
    panda.health.flags_pkt = HEALTH_FLAG_IGNITION_LINE;
    step(catcher, panda, 100);
    for (int i = 0; i < 10; ++i) {
      vehicle_rx(catcher, panda);
      step(catcher, panda, 500);
    }
    catch_programming(catcher, panda);
  }
  for (int drive = 0; drive < 2; ++drive) {
    Panda panda;
    panda.health.flags_pkt = HEALTH_FLAG_IGNITION_LINE;
    Tss3OracleStartupCatcher catcher;
    catcher.update(&panda);
    vehicle_rx(catcher, panda);
    assert(!catcher.active() && panda.sent.empty());
    panda.health.flags_pkt = 0;
    step(catcher, panda, 10);
    assert(catcher.active());
    vehicle_rx(catcher, panda);
    panda.health.flags_pkt = HEALTH_FLAG_IGNITION_LINE;
    step(catcher, panda, 10);
    catch_programming(catcher, panda);
  }
  {
    Panda panda;
    Tss3OracleStartupCatcher catcher;
    catcher.update(&panda);
    vehicle_rx(catcher, panda);
    enabled = false;
    step(catcher, panda, 300);
    const auto before = panda.sent.size();
    vehicle_rx(catcher, panda);
    assert(!catcher.active() && panda.sent.size() == before);
  }
}
'''


class TestStartupCatcher(unittest.TestCase):
  def test_bus_driven_lifecycle(self):
    compiler = shutil.which(os.environ.get("CXX", "c++"))
    if compiler is None:
      self.skipTest("C++ compiler unavailable")
    pandad = Path(__file__).resolve().parents[1]
    source = (pandad / "pandad.cc").read_text()
    catcher = "namespace {" + source.split("namespace {", 1)[1].split("}  // namespace", 1)[0] + "}"
    with tempfile.TemporaryDirectory(prefix="tss3-catcher-") as td:
      tmp = Path(td)
      catcher = catcher.replace('"/tmp/tss3-oracle-native-catch.json"', json.dumps(str(tmp / "catch.json")))
      catcher = catcher.replace('"/tmp/tss3-oracle-native-catch.sock"', json.dumps(str(tmp / "notify.sock")))
      cpp = tmp / "check.cc"
      exe = tmp / "check"
      cpp.write_text(STUBS + f'\n#include "{pandad / "tss3_startup_catcher.h"}"\n' + catcher + SCENARIOS)
      subprocess.run([compiler, "-std=c++17", str(cpp), "-o", str(exe)], check=True, capture_output=True, text=True)
      subprocess.run([str(exe)], check=True, capture_output=True, text=True)


if __name__ == "__main__":
  unittest.main()
